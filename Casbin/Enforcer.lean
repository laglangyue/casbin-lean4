import Casbin.Policy
import Casbin.Pattern
import Casbin.IP

namespace Casbin

abbrev Function := List String → Except String Bool
abbrev MatchingFunction := String → String → Except String Bool

/-- Select named definitions when a model contains more than one policy or matcher. -/
structure Context where
  requestType : String := "r"
  policyType : String := "p"
  effectType : String := "e"
  matcherType : String := "m"
  deriving Repr

structure Decision where
  allow : Bool
  explain : List String := []
  deriving Repr, BEq

/-- Immutable state: mutations return a new enforcer and never persist automatically. -/
structure Enforcer where
  model : Model
  rules : List Rule
  functions : List (String × Function) := []
  roleMatchers : List (String × MatchingFunction) := []
  domainMatchers : List (String × MatchingFunction) := []
  maxHierarchyDepth : Nat := 10

private def builtinNames := ["keyMatch", "keyMatch2", "keyMatch3", "keyMatch5", "regexMatch", "globMatch", "ipMatch"]

private def builtin (name : String) (args : List String) : Except String Bool := do
  let [a, b] := args | throw s!"{name}: expected two string arguments"
  match name with
  | "keyMatch" => return keyMatch a b
  | "keyMatch2" => keyMatch2 a b
  | "keyMatch3" => keyMatch3 a b
  | "keyMatch5" => keyMatch5 a b
  | "regexMatch" => regexMatch a b
  | "globMatch" => globMatch a b
  | "ipMatch" => ipMatch a b
  | _ => throw s!"unknown matcher function: {name}"

private partial def containsExpr (expr needle : Expr) : Bool :=
  expr == needle || match expr with
  | .call _ args => args.any (fun arg => containsExpr arg needle)
  | .eq lhs rhs | .ne lhs rhs | .and lhs rhs | .or lhs rhs =>
    containsExpr lhs needle || containsExpr rhs needle
  | .not arg => containsExpr arg needle
  | .member arg values => containsExpr arg needle || values.any (fun value => containsExpr value needle)
  | _ => false

private def automaticDomainMatchers (model : Model) : List (String × MatchingFunction) := Id.run do
  let some rdef := model.requests.find? (·.name == "r") | return []
  let some pdef := model.policies.find? (·.name == "p") | return []
  let some rdom := rdef.fields[1]? | return []
  let some pdom := pdef.fields[1]? | return []
  let some (_, matcher) := model.matchers.find? (·.1 == "m") | return []
  let needle := Expr.call "keyMatch" [.variable ("r." ++ rdom), .variable ("p." ++ pdom)]
  if !containsExpr matcher needle then return []
  return (model.roles.filter (·.fields.length == 3)).map fun role =>
    (role.name, fun a b => .ok (keyMatch a b))

private partial def validateExpr (e : Enforcer) (expr : Expr) : Except String Bool := do
  -- true is the boolean type; false is the string type.
  match expr with
  | .text _ => return false
  | .boolean _ => return true
  | .variable name =>
    let names := (e.model.requests ++ e.model.policies).flatMap fun defn =>
      defn.fields.map fun field => defn.name ++ "." ++ field
    if !names.contains name then throw s!"unknown matcher variable: {name}"
    return false
  | .call name args =>
    for arg in args do
      if ← validateExpr e arg then throw s!"{name}: arguments must be strings"
    if let some defn := e.model.roles.find? (·.name == name) then
      if args.length != defn.fields.length then throw s!"{name}: incorrect role argument count"
    else if builtinNames.contains name then
      if args.length != 2 then throw s!"{name}: expected two arguments"
    else if !(e.functions.any (·.1 == name)) then
      throw s!"unsupported matcher function: {name}"
    return true
  | .eq lhs rhs | .ne lhs rhs =>
    if (← validateExpr e lhs) != (← validateExpr e rhs) then throw "equality operands have different types"
    return true
  | .and lhs rhs | .or lhs rhs =>
    if !(← validateExpr e lhs) || !(← validateExpr e rhs) then throw "boolean operator requires booleans"
    return true
  | .not arg =>
    if !(← validateExpr e arg) then throw "negation requires a boolean"
    return true
  | .member arg values =>
    let ty ← validateExpr e arg
    for value in values do
      if (← validateExpr e value) != ty then throw "in operands have different types"
    return true

def Enforcer.fromText (modelText policyText : String) (functions : List (String × Function) := []) :
    Except String Enforcer := do
  let model ← Model.parse modelText
  let e : Enforcer := ⟨model, ← parsePolicy model policyText, functions, [], automaticDomainMatchers model, 10⟩
  for (name, expr) in model.matchers do
    if !(← validateExpr e expr) then throw s!"{name}: matcher must produce a boolean"
  return e

def Enforcer.fromFiles (modelPath policyPath : System.FilePath) : IO Enforcer := do
  let model ← IO.FS.readFile modelPath
  let policy ← IO.FS.readFile policyPath
  match Enforcer.fromText model policy with
  | .ok e => return e
  | .error error => throw (IO.userError error)

private def matchName (functions : List (String × MatchingFunction)) (ptype a b : String) :
    Except String Bool :=
  if a == b then .ok true
  else match functions.find? (·.1 == ptype) with
  | some (_, fn) => fn a b
  | none => .ok false

def Enforcer.hasLink (e : Enforcer) (source target : String) (domain : Option String := none)
    (ptype : String := "g") : Except String Bool := do
  let defn ← findDefinition e.model.roles ptype
  if (defn.fields.length == 3) != domain.isSome then throw s!"{ptype}: incorrect domain argument count"
  if ← matchName e.roleMatchers ptype source target then return true
  let mut frontier := [source]
  let mut seen := [source]
  for _ in [:e.maxHierarchyDepth] do
    let mut next := []
    for current in frontier do
      for rule in e.rules do
        if rule.ptype != ptype then continue
        if let some dom := domain then
          if !(← matchName e.domainMatchers ptype dom (rule.values[2]?.getD "")) then continue
        if !(← matchName e.roleMatchers ptype current (rule.values[0]?.getD "")) then continue
        let parent := rule.values[1]?.getD ""
        if ← matchName e.roleMatchers ptype parent target then return true
        if !seen.contains parent && !next.contains parent then next := next ++ [parent]
    if next.isEmpty then return false
    seen := seen ++ next
    frontier := next
  return false

private def callFunction (e : Enforcer) (name : String) (args : List String) : Except String Bool := do
  if e.model.roles.any (·.name == name) then
    match args with
    | [a, b] => e.hasLink a b none name
    | [a, b, dom] => e.hasLink a b (some dom) name
    | _ => throw s!"{name}: invalid role argument count"
  else if let some (_, fn) := e.functions.find? (·.1 == name) then fn args
  else builtin name args

private inductive Value where
  | text (value : String)
  | boolean (value : Bool)
  deriving BEq

private def Value.asBool : Value → Except String Bool
  | .boolean b => .ok b
  | _ => .error "expected boolean value"

private def Value.asText : Value → Except String String
  | .text s => .ok s
  | _ => .error "expected string value"

private partial def evaluate (e : Enforcer) (env : List (String × String)) (expr : Expr) :
    Except String Value := do
  match expr with
  | .text s => return .text s
  | .boolean b => return .boolean b
  | .variable name =>
    match env.find? (·.1 == name) with
    | some (_, value) => return .text value
    | none => throw s!"variable is outside the selected enforcement context: {name}"
  | .call name args =>
    let values ← args.mapM fun arg => do (← evaluate e env arg).asText
    return .boolean (← callFunction e name values)
  | .eq lhs rhs => return .boolean ((← evaluate e env lhs) == (← evaluate e env rhs))
  | .ne lhs rhs => return .boolean ((← evaluate e env lhs) != (← evaluate e env rhs))
  | .and lhs rhs =>
    if !(← (← evaluate e env lhs).asBool) then return .boolean false
    return .boolean (← (← evaluate e env rhs).asBool)
  | .or lhs rhs =>
    if ← (← evaluate e env lhs).asBool then return .boolean true
    return .boolean (← (← evaluate e env rhs).asBool)
  | .not arg => return .boolean (!(← (← evaluate e env arg).asBool))
  | .member arg values =>
    let value ← evaluate e env arg
    for item in values do
      if value == (← evaluate e env item) then return .boolean true
    return .boolean false

private def bindings (defn : Definition) (values : List String) : List (String × String) :=
  defn.fields.zip values |>.map fun (field, value) => (defn.name ++ "." ++ field, value)

private def policyEffect (defn : Definition) (rule : Rule) : String :=
  let values := defn.fields.zip rule.values
  (values.find? (·.1 == "eft")).map Prod.snd |>.getD "allow"

private def orderedPolicies (e : Enforcer) (defn : Definition) : List Rule := Id.run do
  let rules := e.rules.filter (·.ptype == defn.name)
  let some idx := defn.fields.findIdx? (· == "priority") | return rules
  -- Stable insertion sort. The loader and management API validate integer priorities.
  let rank := fun r : Rule => (r.values[idx]?.getD "").toInt?
  let less := fun a b : Rule => match rank a, rank b with
    | some x, some y => x < y
    | some _, none => true
    | _, _ => false
  return rules.foldl (fun sorted r =>
    let before := sorted.takeWhile (fun other => !less r other)
    before ++ [r] ++ sorted.drop before.length) []

private partial def usesPolicy (expr : Expr) (ptype : String) : Bool :=
  match expr with
  | .variable name => name.startsWith (ptype ++ ".")
  | .call _ args => args.any (fun arg => usesPolicy arg ptype)
  | .eq lhs rhs | .ne lhs rhs | .and lhs rhs | .or lhs rhs =>
    usesPolicy lhs ptype || usesPolicy rhs ptype
  | .not arg => usesPolicy arg ptype
  | .member arg values => usesPolicy arg ptype || values.any (fun value => usesPolicy value ptype)
  | _ => false

def Enforcer.enforceEx (e : Enforcer) (request : List String) (ctx : Context := {}) :
    Except String Decision := do
  let rdef ← findDefinition e.model.requests ctx.requestType
  let pdef ← findDefinition e.model.policies ctx.policyType
  if request.length != rdef.fields.length then
    throw s!"request: expected {rdef.fields.length} fields, got {request.length}"
  let some (_, effect) := e.model.effects.find? (·.1 == ctx.effectType) |
    throw s!"unknown effect: {ctx.effectType}"
  let some (_, matcher) := e.model.matchers.find? (·.1 == ctx.matcherType) |
    throw s!"unknown matcher: {ctx.matcherType}"
  let rules := orderedPolicies e pdef
  let direct := rules.isEmpty || !usesPolicy matcher pdef.name
  -- The Go reference short-circuits allow+deny when every policy effect is valid allow.
  let effect := if effect == .allowAndDeny && !direct &&
      rules.all (fun rule => policyEffect pdef rule == "allow") then .allowOverride else effect
  let candidates := if direct then [Rule.mk pdef.name (List.replicate pdef.fields.length "")] else rules
  let mut firstAllow : Option (List String) := none
  for rule in candidates do
    let matched ← (← evaluate e (bindings rdef request ++ bindings pdef rule.values) matcher).asBool
    if !matched then continue
    let eft := if direct then "allow" else policyEffect pdef rule
    let explain := if direct then (rules.head?.map Rule.values).getD [] else rule.values
    match effect with
    | .allowOverride => if eft == "allow" then return ⟨true, explain⟩
    | .denyOverride => if eft == "deny" then return ⟨false, explain⟩
    | .allowAndDeny =>
      if eft == "deny" then return ⟨false, explain⟩
      if eft == "allow" && firstAllow.isNone then firstAllow := some explain
    | .priority =>
      if eft == "allow" then return ⟨true, explain⟩
      if eft == "deny" then return ⟨false, explain⟩
  match effect with
  | .denyOverride => return ⟨true, []⟩
  | .allowAndDeny => return ⟨firstAllow.isSome, firstAllow.getD []⟩
  | _ => return ⟨false, []⟩

def Enforcer.enforce (e : Enforcer) (request : List String) (ctx : Context := {}) : Except String Bool :=
  (e.enforceEx request ctx).map Decision.allow

def Enforcer.batchEnforce (e : Enforcer) (requests : List (List String)) (ctx : Context := {}) :
    Except String (List Bool) := requests.mapM fun request => e.enforce request ctx

def Enforcer.getPolicy (e : Enforcer) (ptype : String := "p") : List (List String) :=
  (e.rules.filter (·.ptype == ptype)).map Rule.values

def Enforcer.getGroupingPolicy (e : Enforcer) (ptype : String := "g") : List (List String) :=
  e.getPolicy ptype

def Enforcer.hasPolicy (e : Enforcer) (values : List String) (ptype : String := "p") : Bool :=
  e.rules.contains ⟨ptype, values⟩

def Enforcer.addPolicy (e : Enforcer) (values : List String) (ptype : String := "p") :
    Except String (Enforcer × Bool) := do
  let rule := Rule.mk ptype values
  rule.validate e.model
  if e.rules.contains rule then return (e, false)
  return ({ e with rules := e.rules ++ [rule] }, true)

def Enforcer.removePolicy (e : Enforcer) (values : List String) (ptype : String := "p") :
    Except String (Enforcer × Bool) := do
  let rule := Rule.mk ptype values
  rule.validate e.model
  if !e.rules.contains rule then return (e, false)
  return ({ e with rules := e.rules.filter (· != rule) }, true)

def Enforcer.addGroupingPolicy (e : Enforcer) (values : List String) (ptype : String := "g") :
    Except String (Enforcer × Bool) := do
  let _ ← findDefinition e.model.roles ptype
  e.addPolicy values ptype

def Enforcer.removeGroupingPolicy (e : Enforcer) (values : List String) (ptype : String := "g") :
    Except String (Enforcer × Bool) := do
  let _ ← findDefinition e.model.roles ptype
  e.removePolicy values ptype

def Enforcer.getRolesForUser (e : Enforcer) (user : String) (domain : Option String := none)
    (ptype : String := "g") : Except String (List String) := do
  let defn ← findDefinition e.model.roles ptype
  if (defn.fields.length == 3) != domain.isSome then throw "incorrect domain argument count"
  let mut roles := []
  for rule in e.rules do
    if rule.ptype != ptype || rule.values[0]? != some user then continue
    if let some dom := domain then
      if rule.values[2]? != some dom then continue
    roles := roles ++ [rule.values[1]?.getD ""]
  return roles.eraseDups

def Enforcer.clearPolicy (e : Enforcer) : Enforcer := { e with rules := [] }

def Enforcer.loadPolicy (e : Enforcer) (source : String) : Except String Enforcer := do
  return { e with rules := ← parsePolicy e.model source }

def Enforcer.savePolicy (e : Enforcer) (path : System.FilePath) : IO Unit :=
  IO.FS.writeFile path (serializePolicy e.rules)

def Enforcer.addMatchingFunction (e : Enforcer) (ptype : String) (fn : MatchingFunction)
    (domain : Bool := false) : Except String Enforcer := do
  let defn ← findDefinition e.model.roles ptype
  if domain && defn.fields.length != 3 then throw "domain matcher requires a three-field role"
  if domain then
    return { e with domainMatchers := (ptype, fn) :: e.domainMatchers.filter (·.1 != ptype) }
  else
    return { e with roleMatchers := (ptype, fn) :: e.roleMatchers.filter (·.1 != ptype) }

end Casbin
