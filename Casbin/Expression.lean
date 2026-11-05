import Casbin.Value
import Casbin.Clock

namespace Casbin

inductive Expr where
  | text (value : String)
  | boolean (value : Bool)
  | number (value : Float)
  | array (values : List Expr)
  | binary (op : String) (lhs rhs : Expr)
  | conditional (test yes no : Expr)
  | neg (arg : Expr)
  | variable (name : String)
  | call (name : String) (args : List Expr)
  | eq (lhs rhs : Expr)
  | ne (lhs rhs : Expr)
  | and (lhs rhs : Expr)
  | or (lhs rhs : Expr)
  | not (arg : Expr)
  | member (arg : Expr) (values : List Expr)
  deriving Repr, BEq

private inductive Token where
  | word (value : String)
  | text (value : String)
  | number (value : String)
  | sym (value : String)
  deriving Repr, BEq

private partial def quoted (quote : Char) (chars : List Char) (acc : String := "") :
    Except String (String × List Char) :=
  match chars with
  | [] => .error "unterminated string literal"
  | c :: cs =>
    if c == quote then .ok (acc, cs)
    else if c == '\\' then
      match cs with
      | [] => .error "unterminated escape"
      | d :: ds => quoted quote ds (acc.push d)
    else quoted quote cs (acc.push c)

private def wordChar (c : Char) : Bool := c.isAlphanum || c == '_' || c == '.'

private partial def numberChars (cs : List Char) (acc : List Char := []) : List Char × List Char :=
  match cs with
  | c :: rest =>
    if c.isDigit || c == '.' then
      numberChars rest (c :: acc)
    else (acc.reverse, cs)
  | [] => (acc.reverse, [])

private partial def tokenize (chars : List Char) : Except String (List Token) := do
  match chars with
  | [] => return []
  | c :: cs =>
    if c.isWhitespace then return ← tokenize cs
    if c == '\'' || c == '"' then
      let (s, rest) ← quoted c cs
      return .text s :: (← tokenize rest)
    if (c == '0' && cs.head? == some 'x') then
      let digits := cs.drop 1 |>.takeWhile (fun d => d.isDigit || ('a' ≤ d.toLower && d.toLower ≤ 'f'))
      if digits.isEmpty then throw "empty hexadecimal number"
      return .number ("0x" ++ String.ofList digits) :: (← tokenize (cs.drop (digits.length + 1)))
    if c.isDigit || (c == '.' && cs.head?.any Char.isDigit) then
      let (digits, rest) := numberChars chars
      return .number (String.ofList digits) :: (← tokenize rest)
    if wordChar c then
      let word := c :: cs.takeWhile wordChar
      return .word (String.ofList word) :: (← tokenize (cs.drop (word.length - 1)))
    match chars with
    | '=' :: '=' :: rest => return .sym "==" :: (← tokenize rest)
    | '!' :: '=' :: rest => return .sym "!=" :: (← tokenize rest)
    | '&' :: '&' :: rest => return .sym "&&" :: (← tokenize rest)
    | '|' :: '|' :: rest => return .sym "||" :: (← tokenize rest)
    | '<' :: '=' :: rest => return .sym "<=" :: (← tokenize rest)
    | '>' :: '=' :: rest => return .sym ">=" :: (← tokenize rest)
    | '=' :: '~' :: rest => return .sym "=~" :: (← tokenize rest)
    | '!' :: '~' :: rest => return .sym "!~" :: (← tokenize rest)
    | '?' :: '?' :: rest => return .sym "??" :: (← tokenize rest)
    | '*' :: '*' :: rest => return .sym "**" :: (← tokenize rest)
    | '<' :: '<' :: rest => return .sym "<<" :: (← tokenize rest)
    | '>' :: '>' :: rest => return .sym ">>" :: (← tokenize rest)
    | _ =>
      if ['(', ')', '[', ']', ',', '!', '<', '>', '+', '-', '*', '/', '%', '?', ':', '~', '&', '|', '^'].contains c then
        return .sym (String.singleton c) :: (← tokenize cs)
      throw s!"unsupported matcher character: {c}"

mutual
private partial def parseConditional (ts : List Token) : Except String (Expr × List Token) := do
  let (test, rest) ← parseOr ts
  match rest with
  | .sym "?" :: rest =>
    let (yes, rest) ← parseConditional rest
    let .sym ":" :: rest := rest | throw "ternary expression requires a colon"
    let (no, rest) ← parseConditional rest
    return (.conditional test yes no, rest)
  | .sym "??" :: rest =>
    let (rhs, rest) ← parseConditional rest
    return (.binary "??" test rhs, rest)
  | _ => return (test, rest)

private partial def parseOr (ts : List Token) : Except String (Expr × List Token) := do
  let (lhs, rest) ← parseAnd ts
  parseOrTail lhs rest

private partial def parseOrTail (lhs : Expr) (ts : List Token) :
    Except String (Expr × List Token) := do
  match ts with
  | .sym "||" :: rest =>
    let (rhs, rest) ← parseAnd rest
    parseOrTail (.or lhs rhs) rest
  | _ => return (lhs, ts)

private partial def parseAnd (ts : List Token) : Except String (Expr × List Token) := do
  let (lhs, rest) ← parseCompare ts
  parseAndTail lhs rest

private partial def parseAndTail (lhs : Expr) (ts : List Token) :
    Except String (Expr × List Token) := do
  match ts with
  | .sym "&&" :: rest =>
    let (rhs, rest) ← parseCompare rest
    parseAndTail (.and lhs rhs) rest
  | _ => return (lhs, ts)

private partial def parseCompare (ts : List Token) : Except String (Expr × List Token) := do
  let (lhs, rest) ← parseArithmetic ts 0
  match rest with
  | .sym "==" :: rest =>
    let (rhs, rest) ← parseArithmetic rest 0
    return (.eq lhs rhs, rest)
  | .sym "!=" :: rest =>
    let (rhs, rest) ← parseArithmetic rest 0
    return (.ne lhs rhs, rest)
  | .word "in" :: .sym opener :: rest =>
    if opener != "(" && opener != "[" then throw "in requires a tuple or list"
    let (args, rest) ← parseArgs (if opener == "(" then ")" else "]") rest
    return (.member lhs args, rest)
  | .word "in" :: rest =>
    let (rhs, rest) ← parseArithmetic rest 0
    return (.binary "in" lhs rhs, rest)
  | .sym op :: rest =>
    if ["<", "<=", ">", ">=", "=~", "!~"].contains op then
      let (rhs, rest) ← parseArithmetic rest 0
      return (.binary op lhs rhs, rest)
    return (lhs, .sym op :: rest)
  | _ => return (lhs, rest)

private partial def parseArithmetic (ts : List Token) (level : Nat) : Except String (Expr × List Token) := do
  if level ≥ 7 then return ← parseUnary ts
  let (lhs, rest) ← parseArithmetic ts (level + 1)
  parseArithmeticTail lhs rest level

private partial def parseArithmeticTail (lhs : Expr) (ts : List Token) (level : Nat) :
    Except String (Expr × List Token) := do
  let ops := match level with
    | 0 => ["|"]
    | 1 => ["^"]
    | 2 => ["&"]
    | 3 => ["<<", ">>"]
    | 4 => ["+", "-"]
    | 5 => ["*", "/", "%"]
    | _ => ["**"]
  match ts with
  | .sym op :: rest =>
    if !ops.contains op then return (lhs, ts)
    let (rhs, rest) ← parseArithmetic rest (level + 1)
    parseArithmeticTail (.binary op lhs rhs) rest level
  | _ => return (lhs, ts)

private partial def parseUnary (ts : List Token) : Except String (Expr × List Token) := do
  match ts with
  | .sym "!" :: rest =>
    let (expr, rest) ← parseUnary rest
    return (.not expr, rest)
  | .sym "-" :: rest =>
    let (expr, rest) ← parseUnary rest
    return (.neg expr, rest)
  | .sym "+" :: rest => parseUnary rest
  | .sym "~" :: rest =>
    let (expr, rest) ← parseUnary rest
    return (.binary "^" expr (.number (-1)), rest)
  | _ => parseAtom ts

private partial def parseAtom (ts : List Token) : Except String (Expr × List Token) := do
  match ts with
  | .text s :: rest => return (match expressionTime s with | some value => .number value | none => .text s, rest)
  | .number s :: rest => return (.number (← parseNumber s), rest)
  | .word "nil" :: rest => return (.variable "nil", rest)
  | .word "true" :: rest => return (.boolean true, rest)
  | .word "false" :: rest => return (.boolean false, rest)
  | .word name :: .sym "(" :: rest =>
    let (args, rest) ← parseArgs ")" rest
    return (.call name args, rest)
  | .word name :: rest => return (.variable name, rest)
  | .sym "(" :: rest =>
    let (expr, rest) ← parseConditional rest
    match rest with
    | .sym ")" :: rest => return (expr, rest)
    | _ => throw "expected closing parenthesis"
  | .sym "[" :: rest =>
    if let .word name :: .sym "]" :: tail := rest then return (.variable name, tail)
    let (args, rest) ← parseArgs "]" rest
    return (.array args, rest)
  | _ => throw "expected matcher expression"

private partial def parseArgs (close : String) (ts : List Token) :
    Except String (List Expr × List Token) := do
  if ts.head? == some (.sym close) then return ([], ts.drop 1)
  let (arg, rest) ← parseConditional ts
  match rest with
  | .sym "," :: rest =>
    if rest.head? == some (.sym close) then throw "trailing comma in argument list"
    let (args, rest) ← parseArgs close rest
    return (arg :: args, rest)
  | .sym c :: rest =>
    if c == close then return ([arg], rest)
    throw s!"expected comma or {close}"
  | _ => throw s!"expected comma or {close}"
end

def Expr.parse (source : String) : Except String Expr := do
  let (expr, rest) ← parseConditional (← tokenize source.toList)
  if !rest.isEmpty then throw s!"unexpected tokens: {repr rest}"
  return expr

private def numberText (value : Float) : String := Id.run do
  if value.isNaN then return "(0 / 0)"
  if value.isInf then return if value < 0 then "(-1 / 0)" else "(1 / 0)"
  let encoded := (Lean.toJson value).compress
  let parts := (encoded.replace "E" "e").splitOn "e"
  if parts.length != 2 then return encoded
  let negative := (parts.headD "").startsWith "-"
  let mantissa := if negative then String.ofList ((parts.headD "").toList.drop 1) else parts.headD ""
  let segments := mantissa.splitOn "."
  let digits := (String.join segments).toList
  let position := Int.ofNat (segments.headD "").length + ((parts[1]?.getD "").toInt?.getD 0)
  let text := if position ≤ 0 then "0." ++ String.ofList (List.replicate (-position).toNat '0' ++ digits)
    else if position.toNat ≥ digits.length then String.ofList (digits ++ List.replicate (position.toNat - digits.length) '0')
    else String.ofList (digits.take position.toNat) ++ "." ++ String.ofList (digits.drop position.toNat)
  return (if negative then "-" else "") ++ text

partial def Expr.toText : Expr → String
  | .text s => (Lean.toJson s).compress
  | .boolean b => if b then "true" else "false"
  | .number n => numberText n
  | .variable name => name
  | .array args => "[" ++ String.intercalate ", " (args.map Expr.toText) ++ "]"
  | .call name args => name ++ "(" ++ String.intercalate ", " (args.map Expr.toText) ++ ")"
  | .binary op a b => "(" ++ a.toText ++ " " ++ op ++ " " ++ b.toText ++ ")"
  | .eq a b => "(" ++ a.toText ++ " == " ++ b.toText ++ ")"
  | .ne a b => "(" ++ a.toText ++ " != " ++ b.toText ++ ")"
  | .and a b => "(" ++ a.toText ++ " && " ++ b.toText ++ ")"
  | .or a b => "(" ++ a.toText ++ " || " ++ b.toText ++ ")"
  | .not a => "!(" ++ a.toText ++ ")"
  | .neg a => "-(" ++ a.toText ++ ")"
  | .conditional test yes no => "(" ++ test.toText ++ " ? " ++ yes.toText ++ " : " ++ no.toText ++ ")"
  | .member value args => "(" ++ value.toText ++ " in (" ++ String.intercalate ", " (args.map Expr.toText) ++ "))"

end Casbin
