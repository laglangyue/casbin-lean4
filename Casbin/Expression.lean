import Std

namespace Casbin

inductive Expr where
  | text (value : String)
  | boolean (value : Bool)
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

private partial def tokenize (chars : List Char) : Except String (List Token) := do
  match chars with
  | [] => return []
  | c :: cs =>
    if c.isWhitespace then return ← tokenize cs
    if c == '\'' || c == '"' then
      let (s, rest) ← quoted c cs
      return .text s :: (← tokenize rest)
    if wordChar c then
      let word := c :: cs.takeWhile wordChar
      return .word (String.ofList word) :: (← tokenize (cs.drop (word.length - 1)))
    match chars with
    | '=' :: '=' :: rest => return .sym "==" :: (← tokenize rest)
    | '!' :: '=' :: rest => return .sym "!=" :: (← tokenize rest)
    | '&' :: '&' :: rest => return .sym "&&" :: (← tokenize rest)
    | '|' :: '|' :: rest => return .sym "||" :: (← tokenize rest)
    | _ =>
      if ['(', ')', '[', ']', ',', '!'].contains c then
        return .sym (String.singleton c) :: (← tokenize cs)
      throw s!"unsupported matcher character: {c}"

mutual
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
  let (lhs, rest) ← parseUnary ts
  match rest with
  | .sym "==" :: rest =>
    let (rhs, rest) ← parseUnary rest
    return (.eq lhs rhs, rest)
  | .sym "!=" :: rest =>
    let (rhs, rest) ← parseUnary rest
    return (.ne lhs rhs, rest)
  | .word "in" :: .sym opener :: rest =>
    if opener != "(" && opener != "[" then throw "in requires a tuple or list"
    let (args, rest) ← parseArgs (if opener == "(" then ")" else "]") rest
    return (.member lhs args, rest)
  | _ => return (lhs, rest)

private partial def parseUnary (ts : List Token) : Except String (Expr × List Token) := do
  match ts with
  | .sym "!" :: rest =>
    let (expr, rest) ← parseUnary rest
    return (.not expr, rest)
  | _ => parseAtom ts

private partial def parseAtom (ts : List Token) : Except String (Expr × List Token) := do
  match ts with
  | .text s :: rest => return (.text s, rest)
  | .word "true" :: rest => return (.boolean true, rest)
  | .word "false" :: rest => return (.boolean false, rest)
  | .word name :: .sym "(" :: rest =>
    let (args, rest) ← parseArgs ")" rest
    return (.call name args, rest)
  | .word name :: rest => return (.variable name, rest)
  | .sym "(" :: rest =>
    let (expr, rest) ← parseOr rest
    match rest with
    | .sym ")" :: rest => return (expr, rest)
    | _ => throw "expected closing parenthesis"
  | _ => throw "expected matcher expression"

private partial def parseArgs (close : String) (ts : List Token) :
    Except String (List Expr × List Token) := do
  if ts.head? == some (.sym close) then return ([], ts.drop 1)
  let (arg, rest) ← parseOr ts
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
  let (expr, rest) ← parseOr (← tokenize source.toList)
  if !rest.isEmpty then throw s!"unexpected tokens: {repr rest}"
  return expr

end Casbin
