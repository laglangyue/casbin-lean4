import Casbin.Enforcer

namespace Casbin

def matchesFilter (rule : List String) (index : Nat) (values : List String) : Bool :=
  (values.zipIdx).all fun (value, offset) => value.isEmpty || rule[index + offset]? == some value

private def validateFilter (e : Enforcer) (ptype : String) (index : Nat) (values : List String) : Except String Unit := do
  let defn ← findDefinition (e.model.policies ++ e.model.roles) ptype
  if index + values.length > defn.fields.length + defn.params then throw "policy filter exceeds field count"

def Enforcer.getFilteredPolicy (e : Enforcer) (index : Nat) (values : List String)
    (ptype : String := "p") : Except String (List (List String)) := do
  validateFilter e ptype index values
  return (e.getPolicy ptype).filter (fun row => matchesFilter row index values)

def Enforcer.getFilteredGroupingPolicy (e : Enforcer) (index : Nat) (values : List String)
    (ptype : String := "g") : Except String (List (List String)) := e.getFilteredPolicy index values ptype

private def replaceRules (e : Enforcer) (rules : List Rule) : Except String (Enforcer × Bool) := do
  for rule in rules do rule.validate e.model
  validateConstraints e.model rules
  return ({ e with rules := rules }, rules != e.rules)

def Enforcer.addPolicies (e : Enforcer) (values : List (List String)) (ptype : String := "p")
    (skipExisting : Bool := false) : Except String (Enforcer × Bool) := do
  let rules := values.map (Rule.mk ptype)
  for rule in rules do rule.validate e.model
  if !skipExisting && rules.any e.rules.contains then return (e, false)
  replaceRules e (e.rules ++ (rules.eraseDups.filter fun rule => !e.rules.contains rule))

def Enforcer.addPoliciesEx (e : Enforcer) (values : List (List String)) (ptype : String := "p") :
    Except String (Enforcer × Bool) := e.addPolicies values ptype true

def Enforcer.removePolicies (e : Enforcer) (values : List (List String)) (ptype : String := "p") :
    Except String (Enforcer × Bool) := do
  let rules := values.map (Rule.mk ptype)
  for rule in rules do rule.validate e.model
  replaceRules e (e.rules.filter fun rule => !rules.contains rule)

def Enforcer.removeFilteredPolicy (e : Enforcer) (index : Nat) (values : List String)
    (ptype : String := "p") : Except String (Enforcer × Bool) := do
  validateFilter e ptype index values
  replaceRules e (e.rules.filter fun rule => rule.ptype != ptype || !matchesFilter rule.values index values)

def Enforcer.updatePolicy (e : Enforcer) (oldValues newValues : List String) (ptype : String := "p") :
    Except String (Enforcer × Bool) := do
  let old := Rule.mk ptype oldValues
  let updated := Rule.mk ptype newValues
  old.validate e.model
  updated.validate e.model
  if !e.rules.contains old then return (e, false)
  if old != updated && e.rules.contains updated then throw "replacement policy already exists"
  replaceRules e (e.rules.map fun rule => if rule == old then updated else rule)

def Enforcer.updatePolicies (e : Enforcer) (oldValues newValues : List (List String))
    (ptype : String := "p") : Except String (Enforcer × Bool) := do
  if oldValues.length != newValues.length then throw "update batch lengths differ"
  let old := oldValues.map (Rule.mk ptype)
  let updated := newValues.map (Rule.mk ptype)
  for rule in old ++ updated do rule.validate e.model
  if old.eraseDups.length != old.length || updated.eraseDups.length != updated.length then
    throw "duplicate policies in update batch"
  if old.any (fun rule => !e.rules.contains rule) then return (e, false)
  if updated.any (fun rule => e.rules.contains rule && !old.contains rule) then
    throw "replacement policy already exists"
  let replacements := old.zip updated
  replaceRules e (e.rules.map fun rule =>
    ((replacements.find? (·.1 == rule)).map Prod.snd).getD rule)

def Enforcer.updateFilteredPolicies (e : Enforcer) (newValues : List (List String))
    (index : Nat) (values : List String) (ptype : String := "p") : Except String (Enforcer × Bool) := do
  let selected ← e.getFilteredPolicy index values ptype
  let rules := e.rules.filter (fun rule => rule.ptype != ptype || !selected.contains rule.values)
  replaceRules e (rules ++ newValues.map (Rule.mk ptype))

def Enforcer.addGroupingPolicies (e : Enforcer) (values : List (List String)) (ptype : String := "g")
    (skipExisting : Bool := false) : Except String (Enforcer × Bool) := do
  let _ ← findDefinition e.model.roles ptype
  e.addPolicies values ptype skipExisting

def Enforcer.removeGroupingPolicies (e : Enforcer) (values : List (List String)) (ptype : String := "g") :
    Except String (Enforcer × Bool) := do
  let _ ← findDefinition e.model.roles ptype
  e.removePolicies values ptype

def Enforcer.updateGroupingPolicy (e : Enforcer) (oldValues newValues : List String) (ptype : String := "g") :
    Except String (Enforcer × Bool) := e.updatePolicy oldValues newValues ptype

def Enforcer.updateGroupingPolicies (e : Enforcer) (oldValues newValues : List (List String)) (ptype : String := "g") :
    Except String (Enforcer × Bool) := e.updatePolicies oldValues newValues ptype

def Enforcer.removeFilteredGroupingPolicy (e : Enforcer) (index : Nat) (values : List String)
    (ptype : String := "g") : Except String (Enforcer × Bool) := e.removeFilteredPolicy index values ptype

def Enforcer.getValuesForField (e : Enforcer) (field : String) (ptype : String := "p") :
    Except String (List String) := do
  let idx ← e.getFieldIndex ptype field
  return ((e.getPolicy ptype).filterMap (·[idx]?)).eraseDups

def Enforcer.getAllSubjects (e : Enforcer) (ptype : String := "p") : Except String (List String) := e.getValuesForField "sub" ptype
def Enforcer.getAllObjects (e : Enforcer) (ptype : String := "p") : Except String (List String) := e.getValuesForField "obj" ptype
def Enforcer.getAllActions (e : Enforcer) (ptype : String := "p") : Except String (List String) := e.getValuesForField "act" ptype
def Enforcer.getAllRoles (e : Enforcer) (ptype : String := "g") : List String :=
  ((e.getGroupingPolicy ptype).filterMap (·[1]?)).eraseDups
def Enforcer.getAllUsers (e : Enforcer) (ptype : String := "g") : List String :=
  let roles := e.getAllRoles ptype
  ((e.getGroupingPolicy ptype).filterMap (·[0]?)).eraseDups.filter (!roles.contains ·)

def Enforcer.setFieldIndex (e : Enforcer) (ptype field : String) (index : Nat) : Except String Enforcer := do
  let defn ← findDefinition e.model.policies ptype
  if index ≥ defn.fields.length then throw "field index exceeds policy width"
  return { e with fieldIndices := (ptype, field, index) :: e.fieldIndices.filter (fun (p, f, _) => p != ptype || f != field) }

def Enforcer.enableEnforce (e : Enforcer) (enabled : Bool) : Enforcer := { e with enabled := enabled }
def Enforcer.enableAcceptJsonRequest (e : Enforcer) (enabled : Bool) : Enforcer := { e with acceptJsonRequest := enabled }

def Enforcer.addFunction (e : Enforcer) (name : String) (fn : Function) : Enforcer :=
  { e with functions := (name, fn) :: e.functions.filter (·.1 != name) }
def Enforcer.addValueFunction (e : Enforcer) (name : String) (fn : ValueFunction) : Enforcer :=
  { e with valueFunctions := (name, fn) :: e.valueFunctions.filter (·.1 != name) }

def Enforcer.addLinkConditionFunction (e : Enforcer) (source target : String)
    (fn : String → List String → Except String Bool) (domain : Option String := none)
    (ptype : String := "g") : Except String Enforcer := do
  let defn ← findDefinition e.model.roles ptype
  if defn.params == 0 then throw "role definition has no condition parameters"
  if (defn.fields.length == 3) != domain.isSome then throw "incorrect condition domain count"
  let condition := LinkCondition.mk ptype source target domain fn none true
  return { e with conditions := condition :: e.conditions.filter (fun c =>
    c.ptype != ptype || c.source != source || c.target != target || c.domain != domain) }

def Enforcer.addTimeCondition (e : Enforcer) (source target : String) (domain : Option String := none)
    (ptype : String := "g") : Except String Enforcer :=
  e.addLinkConditionFunction source target (fun now args => do
    let [start, finish] := args | throw "TimeMatch requires start and end"
    timeMatchAt now start finish) domain ptype

def Enforcer.setLinkConditionParams (e : Enforcer) (source target : String) (params : List String)
    (domain : Option String := none) (ptype : String := "g") : Except String Enforcer := do
  let matchCondition := fun c : LinkCondition => c.ptype == ptype && c.source == source && c.target == target && c.domain == domain
  if !e.conditions.any matchCondition then throw "link condition is not registered"
  let defn ← findDefinition e.model.roles ptype
  if params.length != defn.params then throw "incorrect condition parameter count"
  return { e with conditions := e.conditions.map fun c => if matchCondition c then { c with params := some params } else c }

def Enforcer.enforceWithMatcher (e : Enforcer) (source : String) (request : List Value) (ctx : Context := {}) :
    Except String Decision := do
  let expr ← Expr.parse source
  let name := "__override"
  let model := { e.model with matchers := (name, expr) :: e.model.matchers }
  let current := { e with model := model }
  current.enforceValuesEx request { ctx with matcherType := name }

def Enforcer.batchEnforceWithMatcher (e : Enforcer) (source : String) (requests : List (List Value))
    (ctx : Context := {}) : Except String (List Bool) :=
  requests.mapM fun request => (e.enforceWithMatcher source request ctx).map Decision.allow

end Casbin
