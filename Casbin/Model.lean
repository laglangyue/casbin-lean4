import Casbin.Expression

namespace Casbin

def trim (s : String) : String := s.trimAscii.toString

inductive Effect where
  | allowOverride
  | denyOverride
  | allowAndDeny
  | priority
  | subjectPriority
  | custom (expression : String)
  deriving Repr, BEq

structure Definition where
  name : String
  fields : List String
  params : Nat := 0
  deriving Repr, BEq

structure Model where
  requests : List Definition
  policies : List Definition
  roles : List Definition
  effects : List (String × Effect)
  matchers : List (String × Expr)
  constraints : List (String × Expr) := []
  source : String := ""
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
  | "subjectPriority(p.eft)||deny" => .ok .subjectPriority
  | _ => .ok (.custom value)

def Model.parse (source : String) : Except String Model := do
  let mut secName := ""
  let mut entries : List (String × String × String) := []
  for line in ← logicalLines source do
    if line.startsWith "[" && line.endsWith "]" then
      secName := String.ofList (line.toList.drop 1 |>.take (line.length - 2))
      if !["request_definition", "policy_definition", "role_definition", "policy_effect", "matchers", "constraint_definition"].contains secName then
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
  let mut model : Model := { requests := [], policies := [], roles := [], effects := [], matchers := [], source := source }
  for (sec, key, value) in entries do
    match sec with
    | "request_definition" =>
      model := { model with requests := model.requests ++ [⟨key, ← fields value, 0⟩] }
    | "policy_definition" =>
      model := { model with policies := model.policies ++ [⟨key, ← fields value, 0⟩] }
    | "role_definition" =>
      let parts := value.splitOn "("
      let basic := trim (parts.headD "")
      let basic := if basic.endsWith "," then String.ofList (basic.toList.take (basic.length - 1)) else basic
      let values ← fields basic
      if !(values == ["_", "_"] || values == ["_", "_", "_"]) then
        throw s!"role definitions require two subjects and at most one domain: {key}"
      let mut paramCount := 0
      if parts.length > 1 then
        let paramsText := trim (parts[1]?.getD "")
        if parts.length != 2 || !paramsText.endsWith ")" then throw "invalid role condition parameters"
        let params ← fields (String.ofList (paramsText.toList.take (paramsText.length - 1)))
        if !(params.all (· == "_")) then throw "role condition parameters must be underscores"
        paramCount := params.length
      model := { model with roles := model.roles ++ [⟨key, values, paramCount⟩] }
    | "policy_effect" =>
      let policyNames := entries.filterMap fun (s, k, _) =>
        if s == "policy_definition" then some k else none
      let normalized := policyNames.foldl (fun text name => text.replace (name ++ ".eft") "p.eft") value
      model := { model with effects := model.effects ++ [(key, ← parseEffect normalized)] }
    | "matchers" =>
      model := { model with matchers := model.matchers ++ [(key, ← Expr.parse value)] }
    | "constraint_definition" =>
      model := { model with constraints := model.constraints ++ [(key, ← Expr.parse value)] }
    | _ => throw s!"unsupported section: {sec}"
  let _ ← findDefinition model.requests "r"
  if model.policies.isEmpty then model := { model with policies := [⟨"p", [], 0⟩] }
  let _ ← findDefinition model.policies "p"
  if !(model.effects.any (·.1 == "e")) then throw "missing policy effect e"
  if !(model.matchers.any (·.1 == "m")) then throw "missing matcher m"
  return model

def Effect.toText : Effect → String
  | .allowOverride => "some(where (p.eft == allow))"
  | .denyOverride => "!some(where (p.eft == deny))"
  | .allowAndDeny => "some(where (p.eft == allow)) && !some(where (p.eft == deny))"
  | .priority => "priority(p.eft) || deny"
  | .subjectPriority => "subjectPriority(p.eft) || deny"
  | .custom source => source

def Model.toText (model : Model) : String := Id.run do
  let renderSection : String → List (String × String) → String := fun name (entries : List (String × String)) =>
    if entries.isEmpty then "" else "[" ++ name ++ "]\n" ++
      String.intercalate "\n" (entries.map fun (key, value) => key ++ " = " ++ value) ++ "\n\n"
  let definitions := fun defs => defs.map fun d : Definition =>
    (d.name, String.intercalate ", " d.fields ++
      (if d.params == 0 then "" else ", (" ++ String.intercalate ", " (List.replicate d.params "_") ++ ")"))
  return renderSection "request_definition" (definitions model.requests) ++
    renderSection "policy_definition" (definitions (model.policies.filter (!·.fields.isEmpty))) ++
    renderSection "role_definition" (definitions model.roles) ++
    renderSection "policy_effect" (model.effects.map fun (name, effect) => (name, effect.toText)) ++
    renderSection "matchers" (model.matchers.map fun (name, expr) => (name, expr.toText)) ++
    renderSection "constraint_definition" (model.constraints.map fun (name, expr) => (name, expr.toText))

def Model.fromFile (path : System.FilePath) : IO Model := do
  match Model.parse (← IO.FS.readFile path) with
  | .ok model => return model | .error error => throw (IO.userError error)

end Casbin
