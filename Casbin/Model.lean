import Casbin.Expression

namespace Casbin

def trim (s : String) : String := s.trimAscii.toString

inductive Effect where
  | allowOverride
  | denyOverride
  | allowAndDeny
  | priority
  deriving Repr, BEq

structure Definition where
  name : String
  fields : List String
  deriving Repr, BEq

structure Model where
  requests : List Definition
  policies : List Definition
  roles : List Definition
  effects : List (String × Effect)
  matchers : List (String × Expr)
  deriving Repr

def findDefinition (defs : List Definition) (name : String) : Except String Definition :=
  match defs.find? (·.name == name) with
  | some defn => .ok defn
  | none => .error s!"unknown definition: {name}"

private def stripComment (s : String) : String := Id.run do
  let mut quote : Option Char := none
  let mut escaped := false
  let mut output := ""
  for c in s.toList do
    if escaped then
      output := output.push c
      escaped := false
    else if quote.isSome && c == '\\' then
      output := output.push c
      escaped := true
    else if quote == some c then
      quote := none
      output := output.push c
    else if quote.isNone && (c == '\'' || c == '"') then
      quote := some c
      output := output.push c
    else if quote.isNone && (c == '#' || c == ';') then break
    else output := output.push c
  return trim output

private def logicalLines (source : String) : Except String (List String) := do
  let mut lines := []
  let mut pending := ""
  for raw in source.splitOn "\n" do
    let line := stripComment raw
    if line.endsWith "\\" then
      pending := pending ++ String.ofList (line.toList.take (line.length - 1)) ++ " "
    else if !line.isEmpty then
      lines := lines ++ [pending ++ line]
      pending := ""
  if !pending.isEmpty then throw "unterminated model line continuation"
  return lines

private def fields (value : String) : Except String (List String) := do
  let values := (value.splitOn ",").map trim
  if values.any (fun v => v.isEmpty || !(v.toList.all fun c => c.isAlphanum || c == '_')) then
    throw s!"invalid fields or unsupported conditional role definition: {value}"
  if values.eraseDups.length != values.length && values != List.replicate values.length "_" then
    throw "duplicate definition fields"
  return values

private def parseEffect (value : String) : Except String Effect :=
  match String.ofList (value.toList.filter (!·.isWhitespace)) with
  | "some(where(p.eft==allow))" => .ok .allowOverride
  | "!some(where(p.eft==deny))" => .ok .denyOverride
  | "some(where(p.eft==allow))&&!some(where(p.eft==deny))" => .ok .allowAndDeny
  | "priority(p.eft)||deny" => .ok .priority
  | _ => .error s!"unsupported policy effect: {value}"

def Model.parse (source : String) : Except String Model := do
  let mut secName := ""
  let mut entries : List (String × String × String) := []
  for line in ← logicalLines source do
    if line.startsWith "[" && line.endsWith "]" then
      secName := String.ofList (line.toList.drop 1 |>.take (line.length - 2))
      if !["request_definition", "policy_definition", "role_definition", "policy_effect", "matchers"].contains secName then
        throw s!"unsupported model section: {secName}"
    else
      let parts := line.splitOn "="
      if secName.isEmpty || parts.length < 2 then throw s!"invalid model line: {line}"
      let key := trim (parts.headD "")
      let value := trim (String.intercalate "=" (parts.drop 1))
      if key.isEmpty || value.isEmpty then throw s!"empty model definition: {line}"
      if entries.any (fun (s, k, _) => s == secName && k == key) then
        throw s!"duplicate model definition: {key}"
      entries := entries ++ [(secName, key, value)]
  let mut model : Model := ⟨[], [], [], [], []⟩
  for (sec, key, value) in entries do
    match sec with
    | "request_definition" =>
      model := { model with requests := model.requests ++ [⟨key, ← fields value⟩] }
    | "policy_definition" =>
      model := { model with policies := model.policies ++ [⟨key, ← fields value⟩] }
    | "role_definition" =>
      let values ← fields value
      if !(values == ["_", "_"] || values == ["_", "_", "_"]) then
        throw s!"only ordinary two- or three-field roles are supported: {key}"
      model := { model with roles := model.roles ++ [⟨key, values⟩] }
    | "policy_effect" =>
      let policyNames := entries.filterMap fun (s, k, _) =>
        if s == "policy_definition" then some k else none
      let normalized := policyNames.foldl (fun text name => text.replace (name ++ ".eft") "p.eft") value
      model := { model with effects := model.effects ++ [(key, ← parseEffect normalized)] }
    | "matchers" =>
      model := { model with matchers := model.matchers ++ [(key, ← Expr.parse value)] }
    | _ => throw s!"unsupported section: {sec}"
  let _ ← findDefinition model.requests "r"
  let _ ← findDefinition model.policies "p"
  if !(model.effects.any (·.1 == "e")) then throw "missing policy effect e"
  if !(model.matchers.any (·.1 == "m")) then throw "missing matcher m"
  return model

end Casbin
