import Casbin.Model

namespace Casbin

structure Rule where
  ptype : String
  values : List String
  deriving Repr, BEq

/-- Parse one CSV record; doubled quotes and commas in quoted fields are preserved. -/
private partial def csv (cs : List Char) (acc : String := "")
    (quoted : Bool := false) (closed : Bool := false) (result : List String := []) :
    Except String (List String) := do
  match cs with
  | [] =>
    if quoted then throw "unterminated quoted CSV field"
    return result ++ [if closed then acc else acc.trimAsciiStart.toString]
  | '"' :: '"' :: rest =>
    if quoted then csv rest (acc.push '"') true false result
    else if (trim acc).isEmpty && !closed then csv ('"' :: rest) "" true false result
    else throw "unexpected CSV quote"
  | '"' :: rest =>
    if quoted then csv rest acc false true result
    else if (trim acc).isEmpty && !closed then csv rest "" true false result
    else throw "unexpected CSV quote"
  | ',' :: rest =>
    if quoted then csv rest (acc.push ',') true false result
    else csv rest "" false false (result ++ [if closed then acc else acc.trimAsciiStart.toString])
  | c :: rest =>
    if closed then
      if c.isWhitespace then csv rest acc false true result
      else throw "unexpected text after quoted CSV field"
    else csv rest (acc.push c) quoted false result

def Rule.validate (model : Model) (rule : Rule) : Except String Unit := do
  let defn ← findDefinition (model.policies ++ model.roles) rule.ptype
  if rule.values.length != defn.fields.length then
    throw s!"{rule.ptype}: expected {defn.fields.length} fields, got {rule.values.length}"
  if rule.values.any (fun v => v.contains '\n' || v.contains '\r') then
    throw "policy fields cannot contain line breaks"
  if let some idx := defn.fields.findIdx? (· == "priority") then
    if (rule.values[idx]?.getD "").toInt?.isNone then
      throw "the core port requires an integer priority"

def parsePolicy (model : Model) (source : String) : Except String (List Rule) := do
  let mut rules := []
  let mut lineNumber := 0
  for line in source.splitOn "\n" do
    lineNumber := lineNumber + 1
    let line := trim line
    if line.isEmpty || line.startsWith "#" then continue
    let parts ← (csv line.toList).mapError (fun e => s!"policy line {lineNumber}: {e}")
    let rule := Rule.mk (parts.headD "") (parts.drop 1)
    (rule.validate model).mapError (fun e => s!"policy line {lineNumber}: {e}")
    if !rules.contains rule then rules := rules ++ [rule]
  return rules

private def quoteCSV (value : String) : String :=
  if value.contains ',' || value.contains '"' || trim value != value || value.startsWith "#" then
    "\"" ++ value.replace "\"" "\"\"" ++ "\""
  else value

def serializePolicy (rules : List Rule) : String :=
  String.intercalate "\n" (rules.map fun r =>
    String.intercalate ", " ((r.ptype :: r.values).map quoteCSV)) ++ "\n"

end Casbin
