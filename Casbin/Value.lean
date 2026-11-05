import Lean

namespace Casbin

inductive Value where
  | text (value : String)
  | boolean (value : Bool)
  | number (value : Float)
  | object (fields : List (String × Value))
  | array (items : List Value)
  | null
  deriving Repr, BEq, Inhabited

def Value.asBool : Value → Except String Bool
  | .boolean b => .ok b
  | .number n => .ok (n != 0)
  | _ => .error "expected boolean or numeric matcher result"

def Value.asBoolean : Value → Except String Bool
  | .boolean b => .ok b
  | _ => .error "logical operators require boolean operands"

partial def Value.equal (lhs rhs : Value) : Bool :=
  match lhs, rhs with
  | .object a, .object b => a.length == b.length && a.all (fun (key, value) =>
      (b.find? (·.1 == key)).any (fun (_, other) => Value.equal value other))
  | .array a, .array b => a.length == b.length && (a.zip b).all (fun (x, y) => Value.equal x y)
  | _, _ => lhs == rhs

def Value.asText : Value → Except String String
  | .text s => .ok s
  | _ => .error "expected string value"

def Value.asNumber : Value → Except String Float
  | .number n => .ok n
  | _ => .error "expected numeric value"

partial def Value.fromJson : Lean.Json → Except String Value
  | .str s => .ok (.text s)
  | .bool b => .ok (.boolean b)
  | .null => .ok .null
  | .num n => do return .number (← Lean.fromJson? (.num n))
  | .arr xs => do return .array (← xs.toList.mapM Value.fromJson)
  | .obj xs => do
    return .object (← xs.toList.mapM fun (k, v) => do return (k, ← Value.fromJson v))

partial def Value.toJson : Value → Lean.Json
  | .text s => .str s
  | .boolean b => .bool b
  | .number n => Lean.toJson n
  | .null => .null
  | .array xs => .arr (xs.map Value.toJson).toArray
  | .object xs => Lean.Json.mkObj (xs.map fun (k, v) => (k, v.toJson))

instance : Lean.FromJson Value where fromJson? := Value.fromJson
instance : Lean.ToJson Value where toJson := Value.toJson

def parseNumber (source : String) : Except String Float := do
  if source.startsWith "0x" then
    let chars := source.toList.drop 2
    if chars.isEmpty then throw "empty hexadecimal number"
    let mut value : Nat := 0
    for c in chars do
      let digit := if c.isDigit then c.toNat - '0'.toNat else c.toLower.toNat - 'a'.toNat + 10
      if digit ≥ 16 then throw "invalid hexadecimal digit"
      value := value * 16 + digit
    if value > 18446744073709551615 then throw "hexadecimal literal overflows uint64"
    return value.toFloat
  let source := if source.startsWith "." then "0" ++ source else source
  if (source.splitOn ".e").length > 1 || (source.splitOn ".E").length > 1 then throw "invalid numeric literal"
  let source := if source.endsWith "." then source ++ "0" else source
  let chars := source.toList
  let zeros := chars.takeWhile (· == '0')
  let tail := chars.drop zeros.length
  let source := if !zeros.isEmpty && tail.head?.any Char.isDigit then String.ofList tail
    else if zeros.length > 1 then String.ofList (chars.drop (zeros.length - 1)) else source
  let json ← Lean.Json.parse source
  Lean.fromJson? json

def Value.field (value : Value) (name : String) : Except String Value := do
  match value with
  | .object fields =>
    let some (_, v) := fields.find? (·.1 == name) | throw s!"missing object property: {name}"
    return v
  | .array items =>
    let some idx := name.toNat? | throw s!"invalid array index: {name}"
    let some v := items[idx]? | throw s!"array index out of range: {idx}"
    return v
  | _ => throw s!"cannot read property {name} of scalar value"

def resolveValue (env : List (String × Value)) (name : String) : Except String Value := do
  if let some (_, value) := env.find? (·.1 == name) then return value
  let pieces := name.splitOn "."
  let base := String.intercalate "." (pieces.take 2)
  let some (_, value) := env.find? (·.1 == base) | throw s!"unknown variable: {name}"
  (pieces.drop 2).foldlM Value.field value

end Casbin
