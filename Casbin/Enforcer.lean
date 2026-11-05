import Casbin.Policy
import Casbin.Pattern
import Casbin.IP
import Casbin.Clock

namespace Casbin

abbrev Function := List String → Except String Bool
abbrev MatchingFunction := String → String → Except String Bool
abbrev ValueFunction := List Value → Except String Value

structure LinkCondition where
  ptype : String
  source : String
  target : String
  domain : Option String
  fn : String → List String → Except String Bool
  params : Option (List String) := none
  enabled : Bool := true

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

/-- Entries retain the matcher score as well as the policy effect and explanation. -/
abbrev Effector := Effect → List (String × Float × List String) → Except String Decision

/-- Custom managers receive the current grouping snapshot, so updates cannot leave stale links. -/
structure RoleManager where
  hasLink : List Rule → String → String → Option String → Except String Bool
  getRoles : List Rule → String → Option String → Except String (List String)
  getUsers : List Rule → String → Option String → Except String (List String)

/-- Immutable state: mutations return a new enforcer and never persist automatically. -/
structure Enforcer where
  model : Model
  rules : List Rule
  functions : List (String × Function) := []
  roleMatchers : List (String × MatchingFunction) := []
  domainMatchers : List (String × MatchingFunction) := []
  maxHierarchyDepth : Nat := 10
  valueFunctions : List (String × ValueFunction) := []
  conditions : List LinkCondition := []
  now : String := ""
  enabled : Bool := true
  acceptJsonRequest : Bool := false
  fieldIndices : List (String × String × Nat) := []
  effector : Option Effector := none
  roleManagers : List (String × RoleManager) := []
  roleSnapshot : Option (List Rule) := none

private def builtinNames := ["keyMatch", "keyMatch2", "keyMatch3", "keyMatch4", "keyMatch5", "keyGet", "keyGet2", "keyGet3", "regexMatch", "globMatch", "ipMatch"]

private def builtin (name : String) (args : List String) : Except String Value := do
  if name == "keyGet2" || name == "keyGet3" then
    let [a, b, key] := args | throw s!"{name}: expected three string arguments"
    return .text (← if name == "keyGet2" then keyGet2 a b key else keyGet3 a b key)
  let [a, b] := args | throw s!"{name}: expected two string arguments"
  if name == "keyGet" then return .text (keyGet a b)
  let result : Bool ← match name with
  | "keyMatch" => .ok (keyMatch a b)
  | "keyMatch2" => keyMatch2 a b
  | "keyMatch3" => keyMatch3 a b
  | "keyMatch4" => keyMatch4 a b
  | "keyMatch5" => keyMatch5 a b
  | "regexMatch" => regexMatch a b
  | "globMatch" => globMatch a b
  | "ipMatch" => ipMatch a b
  | _ => throw s!"unknown matcher function: {name}"
  return .boolean result

private partial def containsExpr (expr needle : Expr) : Bool :=
  expr == needle || match expr with
  | .call _ args => args.any (fun arg => containsExpr arg needle)
  | .eq lhs rhs | .ne lhs rhs | .and lhs rhs | .or lhs rhs | .binary _ lhs rhs =>
    containsExpr lhs needle || containsExpr rhs needle
  | .not arg | .neg arg => containsExpr arg needle
  | .array args => args.any (fun arg => containsExpr arg needle)
  | .conditional test yes no => containsExpr test needle || containsExpr yes needle || containsExpr no needle
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

private partial def validateExpr (e : Enforcer) (expr : Expr) : Except String String := do
  match expr with
  | .text _ => return "text"
  | .boolean _ => return "bool"
  | .number _ => return "number"
  | .array values =>
    for v in values do let _ ← validateExpr e v
    return "array"
  | .variable name =>
    if name == "nil" then return "dynamic"
    let names := (e.model.requests ++ e.model.policies).flatMap fun defn =>
      defn.fields.map fun field => defn.name ++ "." ++ field
    let base := String.intercalate "." ((name.splitOn ".").take 2)
    if !names.contains base then throw s!"unknown matcher variable: {name}"
    return if names.contains name then "text" else "dynamic"
  | .call name args =>
    for arg in args do let _ ← validateExpr e arg
    if name == "eval" then
      if args.length != 1 then throw "eval requires one expression argument"
      return "bool"
    if let some defn := e.model.roles.find? (·.name == name) then
      if args.length != defn.fields.length then throw s!"{name}: incorrect role argument count"
    else if builtinNames.contains name then
      let arity := if name == "keyGet2" || name == "keyGet3" then 3 else 2
      if args.length != arity then throw s!"{name}: expected {arity} arguments"
    else if !(e.functions.any (·.1 == name)) && !(e.valueFunctions.any (·.1 == name)) then
      throw s!"unsupported matcher function: {name}"
    return if name.startsWith "keyGet" then "text" else if e.valueFunctions.any (·.1 == name) then "dynamic" else "bool"
  | .eq lhs rhs | .ne lhs rhs =>
    let _ ← validateExpr e lhs
    let _ ← validateExpr e rhs
    return "bool"
  | .and lhs rhs | .or lhs rhs =>
    let _ ← validateExpr e lhs
    let _ ← validateExpr e rhs
    return "bool"
  | .not arg =>
    let _ ← validateExpr e arg
    return "bool"
  | .neg arg => let _ ← validateExpr e arg; return "number"
  | .binary op lhs rhs =>
    let _ ← validateExpr e lhs
    let _ ← validateExpr e rhs
    return if ["<", "<=", ">", ">=", "=~", "!~", "in"].contains op then "bool" else "dynamic"
  | .conditional test yes no =>
    let _ ← validateExpr e test
    let _ ← validateExpr e yes
    let _ ← validateExpr e no
    return "dynamic"
  | .member arg values =>
    let _ ← validateExpr e arg
    for value in values do
      let _ ← validateExpr e value
    return "bool"

def Enforcer.fromText (modelText policyText : String) (functions : List (String × Function) := [])
    (valueFunctions : List (String × ValueFunction) := []) (effector : Option Effector := none) :
    Except String Enforcer := do
  let model ← Model.parse modelText
  let rules ← parsePolicy model policyText
  let e : Enforcer := {
    model := model
    rules := rules
    functions := functions
    domainMatchers := automaticDomainMatchers model
    valueFunctions := valueFunctions
    effector := effector
  }
  if effector.isNone then
    for (_, effect) in model.effects do
      if let .custom source := effect then throw s!"unsupported policy effect: {source}"
  for (name, expr) in model.matchers do
    if !["bool", "number", "dynamic"].contains (← validateExpr e expr) then
      throw s!"{name}: matcher must produce a boolean or number"
  return e

def Enforcer.fromFiles (modelPath policyPath : System.FilePath) : IO Enforcer := do
  let model ← IO.FS.readFile modelPath
  let policy ← IO.FS.readFile policyPath
  match Enforcer.fromText model policy with
  | .ok e => return { e with now := ← currentTime }
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
  let roleRules := e.roleSnapshot.getD e.rules
  if let some (_, manager) := e.roleManagers.find? (·.1 == ptype) then
    return ← manager.hasLink (roleRules.filter (·.ptype == ptype)) source target domain
  if ← matchName e.roleMatchers ptype source target then return true
  let mut frontier := [source]
  let mut seen := [source]
  for _ in [:e.maxHierarchyDepth] do
    let mut next := []
    for current in frontier do
      for rule in roleRules do
        if rule.ptype != ptype then continue
        if let some dom := domain then
          if !(← matchName e.domainMatchers ptype dom (rule.values[2]?.getD "")) then continue
        if !(← matchName e.roleMatchers ptype current (rule.values[0]?.getD "")) then continue
        if let some condition := e.conditions.find? (fun c => c.ptype == ptype &&
            c.source == rule.values[0]?.getD "" && c.target == rule.values[1]?.getD "" &&
            c.domain == (if defn.fields.length == 3 then rule.values[2]? else none)) then
          if condition.enabled && !(← condition.fn e.now (condition.params.getD (rule.values.drop defn.fields.length))) then continue
        let parent := rule.values[1]?.getD ""
        if ← matchName e.roleMatchers ptype parent target then return true
        if !seen.contains parent && !next.contains parent then next := next ++ [parent]
    if next.isEmpty then return false
    seen := seen ++ next
    frontier := next
  return false

private def callFunction (e : Enforcer) (name : String) (args : List Value) : Except String Value := do
  if let some (_, fn) := e.valueFunctions.find? (·.1 == name) then return ← fn args
  let args ← args.mapM Value.asText
  if e.model.roles.any (·.name == name) then
    match args with
    | [a, b] => return .boolean (← e.hasLink a b none name)
    | [a, b, dom] => return .boolean (← e.hasLink a b (some dom) name)
    | _ => throw s!"{name}: invalid role argument count"
  else if let some (_, fn) := e.functions.find? (·.1 == name) then return .boolean (← fn args)
  else builtin name args

private def binaryValue (op : String) (lhs rhs : Value) : Except String Value := do
  if op == "+" && (match lhs, rhs with | .text _, _ | _, .text _ => true | _, _ => false) then
    let render := fun value : Value => match value with | .text s => s | _ => value.toJson.compress
    return .text (render lhs ++ render rhs)
  if op == "in" then
    let .array values := rhs | throw "in requires an array"
    return .boolean (values.any (lhs.equal ·))
  if op == "=~" || op == "!~" then
    let matched ← regexMatch (← lhs.asText) (← rhs.asText)
    return .boolean (if op == "=~" then matched else !matched)
  if let .text a := lhs then
    if let .text b := rhs then
      match op with
      | "+" => return .text (a ++ b)
      | "<" => return .boolean (a < b)
      | "<=" => return .boolean (a ≤ b)
      | ">" => return .boolean (a > b)
      | ">=" => return .boolean (a ≥ b)
      | _ => throw s!"operator {op} does not apply to strings"
  let a ← lhs.asNumber
  let b ← rhs.asNumber
  match op with
  | "+" => return .number (a + b)
  | "-" => return .number (a - b)
  | "*" => return .number (a * b)
  | "/" => return .number (a / b)
  | "%" =>
    let quotient := a / b
    return .number (a - (if quotient < 0 then quotient.ceil else quotient.floor) * b)
  | "**" => return .number (a.pow b)
  | "<" => return .boolean (a < b)
  | "<=" => return .boolean (a ≤ b)
  | ">" => return .boolean (a > b)
  | ">=" => return .boolean (a ≥ b)
  | _ =>
    let x := a.toInt64.toUInt64
    let y := b.toInt64.toUInt64
    let value := match op with
      | "&" => x &&& y
      | "|" => x ||| y
      | "^" => x ^^^ y
      | "<<" => if b < 0 || b ≥ 64 then 0 else a.toUInt64 <<< y
      | ">>" => if b < 0 || b ≥ 64 then 0 else a.toUInt64 >>> y
      | _ => 0
    if !["&", "|", "^", "<<", ">>"].contains op then throw s!"unknown operator: {op}"
    return .number (if op == "<<" || op == ">>" then value.toFloat else value.toInt64.toFloat)

private partial def evaluate (e : Enforcer) (env : List (String × Value)) (expr : Expr) (fuel : Nat := 64) :
    Except String Value := do
  match expr with
  | .text s => return .text s
  | .boolean b => return .boolean b
  | .number n => return .number n
  | .array values => return .array (← values.mapM fun value => evaluate e env value fuel)
  | .variable name =>
    if name == "nil" then return .null
    resolveValue env name
  | .call "eval" [arg] =>
    if fuel == 0 then throw "dynamic eval recursion limit exceeded"
    let source ← (← evaluate e env arg fuel).asText
    let expr ← Expr.parse source
    let _ ← validateExpr e expr
    evaluate e env expr (fuel - 1)
  | .call name args =>
    callFunction e name (← args.mapM fun arg => evaluate e env arg fuel)
  | .binary "??" lhs rhs =>
    let value ← evaluate e env lhs fuel
    if value == .null then evaluate e env rhs fuel else return value
  | .binary op lhs rhs => binaryValue op (← evaluate e env lhs fuel) (← evaluate e env rhs fuel)
  | .neg arg => return .number (-(← (← evaluate e env arg fuel).asNumber))
  | .conditional test yes no =>
    evaluate e env (if ← (← evaluate e env test fuel).asBoolean then yes else no) fuel
  | .eq lhs rhs => return .boolean ((← evaluate e env lhs fuel).equal (← evaluate e env rhs fuel))
  | .ne lhs rhs => return .boolean (!((← evaluate e env lhs fuel).equal (← evaluate e env rhs fuel)))
  | .and lhs rhs =>
    if !(← (← evaluate e env lhs fuel).asBoolean) then return .boolean false
    return .boolean (← (← evaluate e env rhs fuel).asBoolean)
  | .or lhs rhs =>
    if ← (← evaluate e env lhs fuel).asBoolean then return .boolean true
    return .boolean (← (← evaluate e env rhs fuel).asBoolean)
  | .not arg => return .boolean (!(← (← evaluate e env arg fuel).asBoolean))
  | .member arg values =>
    let value ← evaluate e env arg fuel
    for item in values do
      if value.equal (← evaluate e env item fuel) then return .boolean true
    return .boolean false

private def bindings (defn : Definition) (values : List Value) : List (String × Value) :=
  defn.fields.zip values |>.map fun (field, value) => (defn.name ++ "." ++ field, value)

def Enforcer.evaluateExpression (e : Enforcer) (source : String) (environment : List (String × Value) := []) :
    Except String Value := do evaluate e environment (← Expr.parse source)

/-- The upstream legacy helpers return false/empty on invalid patterns; matcher wrappers report errors. -/
def Enforcer.evaluateLegacyBuiltin (_e : Enforcer) (name : String) (args : List Value) : Except String Value :=
  .ok ((args.mapM Value.asText >>= builtin name).toOption.getD
    (if name.startsWith "keyGet" then .text "" else .boolean false))

private def policyEffect (defn : Definition) (rule : Rule) : String :=
  let values := defn.fields.zip rule.values
  (values.find? (·.1 == "eft")).map Prod.snd |>.getD "allow"

def Enforcer.getFieldIndex (e : Enforcer) (ptype field : String) : Except String Nat := do
  if let some (_, _, idx) := e.fieldIndices.find? (fun (p, f, _) => p == ptype && f == field) then return idx
  let defn ← findDefinition e.model.policies ptype
  let some idx := defn.fields.findIdx? (· == field) | throw s!"missing field {ptype}.{field}"
  return idx

private def subjectDepth (e : Enforcer) (subject domain : String) (fuel : Nat)
    (seen : List String := []) : Except String Nat := do
  if seen.contains subject then throw "subjectPriority requires an acyclic role hierarchy"
  match fuel with
  | 0 => return 0
  | fuel + 1 =>
    let links := e.rules.filter fun r => r.ptype == "g" && r.values[0]? == some subject &&
      (r.values[2]?.getD "") == domain
    let mut depth := 0
    for link in links do
      depth := max depth (1 + (← subjectDepth e (link.values[1]?.getD "") domain fuel (subject :: seen)))
    return depth

private def orderedPolicies (e : Enforcer) (defn : Definition) (effect : Effect) : Except String (List Rule) := do
  let rules := e.rules.filter (·.ptype == defn.name)
  if effect == .subjectPriority then
    let subIdx ← e.getFieldIndex defn.name "sub"
    let domIdx := (e.getFieldIndex defn.name "dom").toOption
    let ranked ← rules.mapM fun r => do
      let domain := domIdx.map (fun idx => r.values[idx]?.getD "") |>.getD ""
      return (r, ← subjectDepth e (r.values[subIdx]?.getD "") domain (e.rules.length + 1))
    return (ranked.mergeSort (fun a b => a.2 ≥ b.2)).map Prod.fst
  let some idx := (e.getFieldIndex defn.name "priority").toOption | return rules
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
  | .eq lhs rhs | .ne lhs rhs | .and lhs rhs | .or lhs rhs | .binary _ lhs rhs =>
    usesPolicy lhs ptype || usesPolicy rhs ptype
  | .not arg | .neg arg => usesPolicy arg ptype
  | .array args => args.any (fun arg => usesPolicy arg ptype)
  | .conditional test yes no => usesPolicy test ptype || usesPolicy yes ptype || usesPolicy no ptype
  | .member arg values => usesPolicy arg ptype || values.any (fun value => usesPolicy value ptype)
  | _ => false

def Enforcer.enforceValuesEx (e : Enforcer) (request : List Value) (ctx : Context := {}) :
    Except String Decision := do
  if !e.enabled then return ⟨true, []⟩
  let rdef ← findDefinition e.model.requests ctx.requestType
  let pdef ← findDefinition e.model.policies ctx.policyType
  if request.length != rdef.fields.length then
    throw s!"request: expected {rdef.fields.length} fields, got {request.length}"
  let some (_, effect) := e.model.effects.find? (·.1 == ctx.effectType) |
    throw s!"unknown effect: {ctx.effectType}"
  let some (_, matcher) := e.model.matchers.find? (·.1 == ctx.matcherType) |
    throw s!"unknown matcher: {ctx.matcherType}"
  let request ← request.mapM fun value => do
    if e.acceptJsonRequest then
      if let .text s := value then
        if s.startsWith "{" || s.startsWith "[" then return ← Value.fromJson (← Lean.Json.parse s)
    return value
  let rules ← orderedPolicies e pdef effect
  let direct := rules.isEmpty || !usesPolicy matcher pdef.name
  -- The Go reference short-circuits allow+deny when every policy effect is valid allow.
  let effect := if effect == .allowAndDeny && !direct &&
      rules.all (fun rule => policyEffect pdef rule == "allow") then .allowOverride else effect
  let candidates := if direct then [Rule.mk pdef.name (List.replicate pdef.fields.length "")] else rules
  if let some effector := e.effector then
    let entries : List (String × Float × List String) ← candidates.mapM fun rule => do
      let value ← evaluate e (bindings rdef request ++ bindings pdef (rule.values.map Value.text)) matcher
      let score : Float ← match value with
        | .number n => pure n
        | _ => value.asBool.map (fun flag => if flag then 1 else 0)
      return (if direct then "allow" else policyEffect pdef rule, score, if direct then [] else rule.values)
    return ← effector effect entries
  let mut firstAllow : Option (List String) := none
  for rule in candidates do
    let matched ← (← evaluate e (bindings rdef request ++ bindings pdef (rule.values.map Value.text)) matcher).asBool
    if !matched then continue
    let eft := if direct then "allow" else policyEffect pdef rule
    let explain := if direct then (rules.head?.map Rule.values).getD [] else rule.values
    match effect with
    | .allowOverride => if eft == "allow" then return ⟨true, explain⟩
    | .denyOverride => if eft == "deny" then return ⟨false, explain⟩
    | .allowAndDeny =>
      if eft == "deny" then return ⟨false, explain⟩
      if eft == "allow" && firstAllow.isNone then firstAllow := some explain
    | .priority | .subjectPriority =>
      if eft == "allow" then return ⟨true, explain⟩
      if eft == "deny" then return ⟨false, explain⟩
    | .custom source => throw s!"custom effector required for {source}"
  match effect with
  | .denyOverride => return ⟨true, []⟩
  | .allowAndDeny => return ⟨firstAllow.isSome, firstAllow.getD []⟩
  | _ => return ⟨false, []⟩

def Enforcer.enforceEx (e : Enforcer) (request : List String) (ctx : Context := {}) : Except String Decision :=
  e.enforceValuesEx (request.map Value.text) ctx

def Enforcer.enforceValues (e : Enforcer) (request : List Value) (ctx : Context := {}) : Except String Bool :=
  (e.enforceValuesEx request ctx).map Decision.allow

def Enforcer.enforceValuesIO (e : Enforcer) (request : List Value) (ctx : Context := {}) : IO Decision := do
  let current := { e with now := ← currentTime }
  match current.enforceValuesEx request ctx with
  | .ok result => return result
  | .error error => throw (IO.userError error)

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
  let rules := e.rules ++ [rule]
  validateConstraints e.model rules
  return ({ e with rules := rules }, true)

def Enforcer.removePolicy (e : Enforcer) (values : List String) (ptype : String := "p") :
    Except String (Enforcer × Bool) := do
  let rule := Rule.mk ptype values
  rule.validate e.model
  if !e.rules.contains rule then return (e, false)
  let rules := e.rules.filter (· != rule)
  validateConstraints e.model rules
  return ({ e with rules := rules }, true)

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
  let roleRules := e.roleSnapshot.getD e.rules
  if let some (_, manager) := e.roleManagers.find? (·.1 == ptype) then
    return ← manager.getRoles (roleRules.filter (·.ptype == ptype)) user domain
  let mut roles := []
  for rule in roleRules do
    if rule.ptype != ptype || !(← matchName e.roleMatchers ptype user (rule.values[0]?.getD "")) then continue
    if let some dom := domain then
      if !(← matchName e.domainMatchers ptype dom (rule.values[2]?.getD "")) then continue
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
