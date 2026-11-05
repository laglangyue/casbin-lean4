import Casbin.Rbac
import Std.Sync.Mutex

namespace Casbin

structure PolicyFilter where
  p : List String := []
  g : List String := []
  named : List (String × List String) := []
  deriving Repr, BEq

def PolicyFilter.accepts (filter : PolicyFilter) (rule : Rule) : Bool :=
  let values := ((filter.named.find? (·.1 == rule.ptype)).map Prod.snd).getD
    (if rule.ptype.startsWith "g" then filter.g else filter.p)
  matchesFilter rule.values 0 values

/-- Adapter callbacks receive complete validated records. Save is atomic at the adapter boundary. -/
structure Adapter where
  load : Model → IO (List Rule)
  save : Model → List Rule → IO Unit
  supportsIncremental : Bool := false
  apply : Option (Model → List Rule → List Rule → IO Unit) := none

def mergeRuleChanges (before after current : List Rule) : Except String (List Rule) := do
  let removed := before.filter (!after.contains ·)
  let added := after.filter (!before.contains ·)
  if removed.any (!current.contains ·) then throw "adapter conflict: policy was removed or updated"
  if !removed.isEmpty && added.any current.contains then throw "adapter conflict: replacement already exists"
  if removed.length == added.length then
    let pairs := removed.zip added
    return current.map fun r => ((pairs.find? (·.1 == r)).map Prod.snd).getD r
  return (current.filter (!removed.contains ·) ++ added).eraseDups

private def unwrapAdapter (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError error)

def Adapter.file (path : System.FilePath) : Adapter := {
  load := fun model => do unwrapAdapter (parsePolicy model (← IO.FS.readFile path))
  save := fun model rules => do
    for rule in rules do unwrapAdapter (rule.validate model)
    unwrapAdapter (validateConstraints model rules)
    let temporary := path.toString ++ ".casbin-tmp-" ++ toString (← IO.monoNanosNow)
    try
      IO.FS.writeFile temporary (serializePolicy rules)
      IO.FS.rename temporary path
    catch error =>
      try IO.FS.removeFile temporary catch _ => pure ()
      throw error
}

def Adapter.memory (initial : List Rule := []) : IO Adapter := do
  let state ← Std.Mutex.new initial
  return {
    load := fun model => state.atomically do
      let rules ← get
      for rule in rules do unwrapAdapter (rule.validate model)
      return rules
    save := fun model rules => state.atomically do
      for rule in rules do unwrapAdapter (rule.validate model)
      unwrapAdapter (validateConstraints model rules)
      set rules
    supportsIncremental := true
    apply := some (fun model before after => state.atomically do
      let rules ← unwrapAdapter (mergeRuleChanges before after (← get))
      for rule in rules do unwrapAdapter (rule.validate model)
      unwrapAdapter (validateConstraints model rules)
      set rules)
  }

def Adapter.string (initial : String) : IO Adapter := do
  let state ← Std.Mutex.new initial
  return {
    load := fun model => state.atomically do unwrapAdapter (parsePolicy model (← get))
    save := fun model rules => state.atomically do
      for rule in rules do unwrapAdapter (rule.validate model)
      unwrapAdapter (validateConstraints model rules)
      set (serializePolicy rules)
  }

private def sqliteQuote (value : String) : String := "'" ++ value.replace "'" "''" ++ "'"

private def decodeSqliteRows (model : Model) (source : String) : IO (List Rule) := do
  let json ← unwrapAdapter (Lean.Json.parse (trim source))
  let rows ← unwrapAdapter json.getArr?
  rows.toList.mapM fun row => do
    let ptype ← unwrapAdapter (row.getObjValAs? String "ptype")
    let values ← unwrapAdapter (row.getObjValAs? (List String) "values")
    let rule := Rule.mk ptype values
    unwrapAdapter (rule.validate model)
    return rule

private def sqliteSelect :=
  "SELECT json_group_array(json_object('ptype',ptype,'values',json(vals))) FROM (SELECT * FROM casbin_rule ORDER BY seq);"

private def executeSqlite (path : System.FilePath) (executable sql : String) : IO Unit := do
  let process ← IO.Process.spawn { cmd := executable, args := #["-bail", path.toString], stdin := .piped, stdout := .piped, stderr := .piped }
  process.stdin.putStr sql
  let (_, process) ← process.takeStdin
  let errors ← process.stderr.readToEnd
  let code ← process.wait
  if code != 0 then throw (IO.userError errors)

/-- SQLite persistence uses the installed sqlite3 command; no database credentials are needed. -/
def Adapter.sqlite (path : System.FilePath) (executable : String := "sqlite3") : Adapter := {
  load := fun model => do
    let output ← IO.Process.output { cmd := executable, args := #[path.toString,
      "CREATE TABLE IF NOT EXISTS casbin_rule (seq INTEGER PRIMARY KEY, ptype TEXT NOT NULL, vals TEXT NOT NULL); SELECT json_group_array(json_object('ptype',ptype,'values',json(vals))) FROM (SELECT * FROM casbin_rule ORDER BY seq);"] }
    if output.exitCode != 0 then throw (IO.userError output.stderr)
    decodeSqliteRows model output.stdout
  save := fun model rules => do
    for rule in rules do unwrapAdapter (rule.validate model)
    unwrapAdapter (validateConstraints model rules)
    let statements := rules.map fun rule =>
      "INSERT INTO casbin_rule(ptype,vals) VALUES(" ++ sqliteQuote rule.ptype ++ "," ++
        sqliteQuote (Lean.toJson rule.values).compress ++ ");"
    let sql := "BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS casbin_rule (seq INTEGER PRIMARY KEY, ptype TEXT NOT NULL, vals TEXT NOT NULL); DELETE FROM casbin_rule; " ++ String.join statements ++ "COMMIT;"
    -- Send records on stdin so policies never become shell commands or command-line arguments.
    executeSqlite path executable sql
  supportsIncremental := true
  apply := some (fun model before after => do
    for rule in after do unwrapAdapter (rule.validate model)
    unwrapAdapter (validateConstraints model after)
    let removed := before.filter (!after.contains ·)
    let added := after.filter (!before.contains ·)
    let condition := fun r : Rule => "ptype=" ++ sqliteQuote r.ptype ++ " AND vals=" ++ sqliteQuote (Lean.toJson r.values).compress
    let mut sql := "CREATE TEMP TABLE casbin_guard(ok INTEGER CHECK(ok=1));"
    for rule in removed do
      sql := sql ++ "INSERT INTO casbin_guard SELECT EXISTS(SELECT 1 FROM casbin_rule WHERE " ++ condition rule ++ ");"
    if !removed.isEmpty then
      for rule in added do
        sql := sql ++ "INSERT INTO casbin_guard SELECT NOT EXISTS(SELECT 1 FROM casbin_rule WHERE " ++ condition rule ++ ");"
    if removed.length == added.length then
      for (oldRule, newRule) in removed.zip added do
        sql := sql ++ "UPDATE casbin_rule SET ptype=" ++ sqliteQuote newRule.ptype ++ ",vals=" ++
          sqliteQuote (Lean.toJson newRule.values).compress ++ " WHERE " ++ condition oldRule ++ ";"
    else
      for rule in removed do sql := sql ++ "DELETE FROM casbin_rule WHERE " ++ condition rule ++ ";"
      for rule in added do
        sql := sql ++ "INSERT INTO casbin_rule(ptype,vals) SELECT " ++ sqliteQuote rule.ptype ++ "," ++
          sqliteQuote (Lean.toJson rule.values).compress ++ " WHERE NOT EXISTS(SELECT 1 FROM casbin_rule WHERE " ++ condition rule ++ ");"
    let process ← IO.Process.spawn { cmd := executable, args := #["-bail", path.toString], stdin := .piped, stdout := .piped, stderr := .piped }
    try
      process.stdin.putStrLn ("BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS casbin_rule (seq INTEGER PRIMARY KEY, ptype TEXT NOT NULL, vals TEXT NOT NULL); " ++ sqliteSelect)
      process.stdin.flush
      let current ← decodeSqliteRows model (← process.stdout.getLine)
      let merged ← unwrapAdapter (mergeRuleChanges before after current)
      unwrapAdapter (validateConstraints model merged)
      -- Keep the same database transaction open while Lean validates the merged snapshot.
      process.stdin.putStrLn (sql ++ "COMMIT;\n.quit")
      process.stdin.flush
      let (_, process) ← process.takeStdin
      let errors ← process.stderr.readToEnd
      let code ← process.wait
      if code != 0 then throw (IO.userError errors)
    catch error =>
      try process.kill catch _ => pure ()
      try let _ ← process.wait; pure () catch _ => pure ()
      throw error)
}

end Casbin
