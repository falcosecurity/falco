--[[
   Falco grammar and parser.

   Much of the scaffolding and helpers was derived from Andre Murbach Maidl's Lua parser (https://github.com/andremm/lua-parser).

   Parses regular filters following the existing sysdig filter syntax (*), extended to support "macro" terms, which are just identifiers.

   (*) There is currently one known difference with the syntax implemented in libsinsp: In libsinsp, field names cannot start with 'a', 'o', or 'n'. With this parser they can.

--]]

local parser = {}

parser.verbose = false

function parser.set_verbose(verbose)
   parser.verbose = verbose
end

local lpeg = require "lpeg"

lpeg.locale(lpeg)

local P, S, V = lpeg.P, lpeg.S, lpeg.V
local C, Carg, Cb, Cc = lpeg.C, lpeg.Carg, lpeg.Cb, lpeg.Cc
local Cf, Cg, Cmt, Cp, Ct = lpeg.Cf, lpeg.Cg, lpeg.Cmt, lpeg.Cp, lpeg.Ct
local alpha, digit, alnum = lpeg.alpha, lpeg.digit, lpeg.alnum
local xdigit = lpeg.xdigit
local space = lpeg.space


-- error message auxiliary functions

-- creates an error message for the input string
local function syntaxerror (errorinfo, pos, msg)
  local error_msg = "%s: syntax error, %s"
  return string.format(error_msg, pos, msg)
end

-- gets the farthest failure position
local function getffp (s, i, t)
  return t.ffp or i, t
end

-- gets the table that contains the error information
local function geterrorinfo ()
  return Cmt(Carg(1), getffp) * (C(V"OneWord") + Cc("EOF")) /
  function (t, u)
    t.unexpected = u
    return t
  end
end

-- creates an errror message using the farthest failure position
local function errormsg ()
  return geterrorinfo() /
  function (t)
    local p = t.ffp or 1
    local msg = "unexpected '%s', expecting %s"
    msg = string.format(msg, t.unexpected, t.expected)
    return nil, syntaxerror(t, p, msg)
  end
end

-- reports a syntactic error
local function report_error ()
  return errormsg()
end

--- sets the farthest failure position and the expected tokens
local function setffp (s, i, t, n)
  if not t.ffp or i > t.ffp then
    t.ffp = i
    t.list = {} ; t.list[n] = n
    t.expected = "'" .. n .. "'"
  elseif i == t.ffp then
    if not t.list[n] then
      t.list[n] = n
      t.expected = "'" .. n .. "', " .. t.expected
    end
  end
  return false
end

local function updateffp (name)
  return Cmt(Carg(1) * Cc(name), setffp)
end

-- regular combinators and auxiliary functions

local function token (pat, name)
  return pat * V"Skip" + updateffp(name) * P(false)
end

local function symb (str)
  return token (P(str), str)
end

local function kw (str)
  return token (P(str) * -V"idRest", str)
end


local function list (pat, sep)
   return Ct(pat^-1 * (sep * pat^0)^0) / function(elements) return {type = "List", elements=elements} end
end

--http://lua-users.org/wiki/StringTrim
function trim(s)
   if (type(s) ~= "string") then return s end
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

local function terminal (tag)
   -- Rather than trim the whitespace in this way, it would be nicer to exclude it from the capture...
   return token(V(tag), tag) / function (tok) return { type = tag, value = trim(tok)} end
end

local function unaryboolop (op, e)
  return { type = "UnaryBoolOp", operator = op, argument = e }
end

local function unaryrelop (e, op)
  return { type = "UnaryRelOp", operator = op, argument = e }
end

local function binaryop (e1, op, e2)
  if not op then
     return e1
  else
     return { type = "BinaryBoolOp", operator = op, left = e1, right = e2 }
  end
end

local function bool (pat, sep)
  return Cf(pat * Cg(sep * pat)^0, binaryop)
end

local function rel (left, sep, right)
   return left * sep * right / function(e1, op, e2) return { type = "BinaryRelOp", operator = op, left = e1, right = e2 } end
end

local function fix_str (str)
  str = string.gsub(str, "\\a", "\a")
  str = string.gsub(str, "\\b", "\b")
  str = string.gsub(str, "\\f", "\f")
  str = string.gsub(str, "\\n", "\n")
  str = string.gsub(str, "\\r", "\r")
  str = string.gsub(str, "\\t", "\t")
  str = string.gsub(str, "\\v", "\v")
  str = string.gsub(str, "\\\n", "\n")
  str = string.gsub(str, "\\\r", "\n")
  str = string.gsub(str, "\\'", "'")
  str = string.gsub(str, '\\"', '"')
  str = string.gsub(str, '\\\\', '\\')
  return str
end

-- grammar


local function filter(e)
   return {type = "Filter", value=e}
end

local function rule(filter)
   return {type = "Rule", filter = filter}
end

local G = {
   V"Start", -- Entry rule

   Start = V"Skip" * (V"Comment" + V"Rule" / rule)^-1 * -1 + report_error();

  -- Grammar
   Comment = P"#" * P(1)^0;

   Rule = V"Filter" / filter * ((V"Skip")^-1 );

   Filter = V"OrExpression";
  OrExpression =
     bool(V"AndExpression", V"OrOp");

  AndExpression =
     bool(V"NotExpression", V"AndOp");

  NotExpression =
     V"UnaryBoolOp" * V"NotExpression" / unaryboolop +
     V"ExistsExpression";

  ExistsExpression =
     terminal "FieldName" * V"ExistsOp" / unaryrelop +
     V"MacroExpression";

  MacroExpression =
     terminal "Macro" +
     V"RelationalExpression";

  RelationalExpression =
     rel(terminal "FieldName", V"RelOp", V"Value") +
     rel(terminal "FieldName", V"InOp", V"InList") +
     V"PrimaryExp";

  PrimaryExp = symb("(") * V"Filter" * symb(")");

  FuncArgs = symb("(") * list(V"Value", symb(",")) * symb(")");

  -- Terminals
  Value = terminal "Number" + terminal "String" + terminal "BareString";

  InList = symb("(") * list(V"Value", symb(",")) * symb(")");


  -- Lexemes
  Space = space^1;
  Skip = (V"Space")^0;
  idStart = alpha + P("_");
  idRest = alnum + P("_");
  Identifier = V"idStart" * V"idRest"^0;
  Macro = V"idStart" * V"idRest"^0 * -P".";
  FieldName = V"Identifier" * (P"." + V"Identifier")^1 * (P"[" * V"Int" * P"]")^-1;
  Name = C(V"Identifier") * -V"idRest";
  Hex = (P("0x") + P("0X")) * xdigit^1;
  Expo = S("eE") * S("+-")^-1 * digit^1;
  Float = (((digit^1 * P(".") * digit^0) +
          (P(".") * digit^1)) * V"Expo"^-1) +
          (digit^1 * V"Expo");
  Int = digit^1;
  Number = C(V"Hex" + V"Float" + V"Int") /
           function (n) return tonumber(n) end;
  String = (P'"' * C(((P'\\' * P(1)) + (P(1) - P'"'))^0) * P'"' +  P"'" * C(((P"\\" * P(1)) + (P(1) - P"'"))^0) * P"'")  / function (s) return fix_str(s) end;
  BareString = C(((P(1) - S' (),='))^1);

  OrOp = kw("or") / "or";
  AndOp = kw("and") / "and";
  Colon = kw(":");
  RelOp = symb("=") / "=" +
          symb("==") / "==" +
          symb("!=") / "!=" +
          symb("<=") / "<=" +
          symb(">=") / ">=" +
          symb("<") / "<" +
          symb(">") / ">" +
          symb("contains") / "contains" +
          symb("icontains") / "icontains" +
          symb("startswith") / "startswith";
  InOp = kw("in") / "in";
  UnaryBoolOp = kw("not") / "not";
  ExistsOp = kw("exists") / "exists";

  -- for error reporting
  OneWord = V"Name" + V"Number" + V"String" +  P(1);
}

--[[
   Parses a single filter and returns the AST.
--]]
function parser.parse_filter (subject)
  local errorinfo = { subject = subject }
  lpeg.setmaxstack(1000)
  local ast, error_msg = lpeg.match(G, subject, nil, errorinfo)
  return ast, error_msg
end

function print_ast(ast, level)
   local t = ast.type
   level = level or 0
   local prefix = string.rep(" ", level*4)
   level = level + 1

   if t == "Rule" then
      print_ast(ast.filter, level)
   elseif t == "Filter" then
      print_ast(ast.value, level)

   elseif t == "BinaryBoolOp" or t == "BinaryRelOp" then
      print(prefix..ast.operator)
      print_ast(ast.left, level)
      print_ast(ast.right, level)

   elseif t == "UnaryRelOp" or t == "UnaryBoolOp" then
      print (prefix..ast.operator)
      print_ast(ast.argument, level)

   elseif t == "List" then
      for i, v in ipairs(ast.elements) do
         print_ast(v, level)
      end

   elseif t == "FieldName" or t == "Number" or t == "String" or t == "BareString" or t == "Macro" then
      print (prefix..t.." "..ast.value)

   elseif t == "MacroDef" then
      -- don't print for now
   else
      error ("Unexpected type in print_ast: "..t)
   end
end
parser.print_ast = print_ast

-- Traverse the provided ast and call the provided callback function
-- for any nodes of the specified type. The callback function should
-- have the signature:
--     cb(ast_node, ctx)
-- ctx is optional.
function traverse_ast(ast, node_types, cb, ctx)
   local t = ast.type

   if node_types[t] ~= nil then
      cb(ast, ctx)
   end

   if t == "Rule" then
      traverse_ast(ast.filter, node_types, cb, ctx)

   elseif t == "Filter" then
      traverse_ast(ast.value, node_types, cb, ctx)

   elseif t == "BinaryBoolOp" or t == "BinaryRelOp" then
      traverse_ast(ast.left, node_types, cb, ctx)
      traverse_ast(ast.right, node_types, cb, ctx)

   elseif t == "UnaryRelOp" or t == "UnaryBoolOp" then
      traverse_ast(ast.argument, node_types, cb, ctx)

   elseif t == "List" then
      for i, v in ipairs(ast.elements) do
         traverse_ast(v, node_types, cb, ctx)
      end

   elseif t == "MacroDef" then
      traverse_ast(ast.value, node_types, cb, ctx)

   elseif t == "FieldName" or t == "Number" or t == "String" or t == "BareString" or t == "Macro" then
      -- do nothing, no traversal needed

   else
      error ("Unexpected type in traverse_ast: "..t)
   end
end
parser.traverse_ast = traverse_ast

return parser
