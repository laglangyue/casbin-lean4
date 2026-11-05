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
  let isRole := model.roles.any (·.name == rule.ptype)
  let expected := defn.fields.length + defn.params
  if (isRole && rule.values.length < expected) || (!isRole && rule.values.length != expected) then
    throw s!"{rule.ptype}: expected {expected} fields, got {rule.values.length}"
  if rule.values.any (fun v => v.contains '\n' || v.contains '\r') then
    throw "policy fields cannot contain line breaks"

def validateConstraints (model : Model) (rules : List Rule) : Except String Unit := do
  if model.constraints.isEmpty then return
  if !(model.roles.any (·.name == "g")) then throw "constraints require role definition g"
  let links := rules.filter (·.ptype == "g")
  let users := (links.map (fun r => r.values[0]?.getD "")).eraseDups
  let rolesFor := fun user => (links.filter (fun r => r.values[0]? == some user)).map
    (fun r => r.values[1]?.getD "") |>.eraseDups
  for (key, expr) in model.constraints do
    match expr with
    | .call "sod" [.text a, .text b] =>
      for user in users do
        let roles := rolesFor user
        if roles.contains a && roles.contains b then throw s!"constraint {key}: {user} cannot hold both {a} and {b}"
    | .call "sodMax" [.array values, .number limit] =>
      if limit < 0 || limit.floor != limit then throw s!"constraint {key}: invalid maximum"
      let roles ← values.mapM fun value => match value with
        | .text name => .ok name
        | _ => .error "sodMax requires string role names"
      if roles.isEmpty then throw "sodMax requires at least one role"
      for user in users do
        if ((rolesFor user).filter roles.contains).length > limit.toUInt64.toNat then
          throw s!"constraint {key}: too many roles assigned to {user}"
    | .call "roleMax" [.text role, .number limit] =>
      if limit < 0 || limit.floor != limit then throw s!"constraint {key}: invalid maximum"
      if (users.filter (fun user => (rolesFor user).contains role)).length > limit.toUInt64.toNat then
        throw s!"constraint {key}: too many users hold {role}"
    | .call "rolePre" [.text role, .text prerequisite] =>
      for user in users do
        let roles := rolesFor user
        if roles.contains role && !roles.contains prerequisite then
          throw s!"constraint {key}: {user} requires {prerequisite} before {role}"
    | _ => throw s!"unrecognized constraint: {key}"

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
  validateConstraints model rules
  return rules

private def quoteCSV (value : String) : String :=
  if value.contains ',' || value.contains '"' || trim value != value || value.startsWith "#" then
    "\"" ++ value.replace "\"" "\"\"" ++ "\""
  else value

def serializePolicy (rules : List Rule) : String :=
  String.intercalate "\n" (rules.map fun r =>
    String.intercalate ", " ((r.ptype :: r.values).map quoteCSV)) ++ "\n"

end Casbin
