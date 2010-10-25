# -*- coding: utf-8 -*-
"""
    pygments.lexers.xquery
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    Lexer for xquery language.

    :copyright: Copyright 2010 by Steve Spigarelli
    :license: BSD, see LICENSE for details.
"""

import re

from pygments.lexer import Lexer, RegexLexer, ExtendedRegexLexer, bygroups, include, do_insertions
from pygments.token import Text, Comment, Operator, Keyword, Name, \
     String, Number, Punctuation, Literal, Generic
from pygments.lexers.web import XmlLexer


__all__ = ['XQueryLexer']


class XQueryLexer(ExtendedRegexLexer):
		"""
		An XQuery lexer, parsing a stream and outputting the tokens
		needed to highlight xquery code.
		"""
		name = 'XQuery'
		aliases = ['xquery', 'xqy']
		filenames = ['*.xqy', '*.xquery']
		mimetypes = ['text/xquery', 'application/xquery']

 		xquery_parse_state = []

# FIX UNICODE LATER
		#ncnamestartchar = ur"[A-Z]|_|[a-z]|[\u00C0-\u00D6]|[\u00D8-\u00F6]|[\u00F8-\u02FF]|[\u0370-\u037D]|[\u037F-\u1FFF]|[\u200C-\u200D]|[\u2070-\u218F]|[\u2C00-\u2FEF]|[\u3001-\uD7FF]|[\uF900-\uFDCF]|[\uFDF0-\uFFFD]|[\u10000-\uEFFFF]"
		ncnamestartchar = r"[A-Z]|_|[a-z]"
# FIX UNICODE LATER
		#ncnamechar = ncnamestartchar + ur"|-|\.|[0-9]|\u00B7|[\u0300-\u036F]|[\u203F-\u2040]"
		ncnamechar = ncnamestartchar + r"|-|\.|[0-9]"
		ncname = "((%s)+(%s)*)" % (ncnamestartchar, ncnamechar)
		pitarget_namestartchar = r"[A-KN-WY-Z]|_|:|[a-kn-wy-z]"
		pitarget_namechar = pitarget_namestartchar + r"|-|\.|[0-9]"
		pitarget = "(%s)+(%s)*" % (pitarget_namestartchar, pitarget_namechar)
		prefixedname = "%s:%s" % (ncname, ncname)
		unprefixedname = ncname
		qname = "((%s)|(%s))" %(prefixedname, unprefixedname)

		entityref = r'&(lt|gt|amp|quot|apos);'
	 	charref = r'&#[0-9]+;|&#x[0-9a-fA-F]+;'

		stringdouble = r'("((' + entityref + r')|(' + charref + r')|("")|([^&"]))*")'
		stringsingle = r"('((" + entityref + r")|(" + charref + r")|('')|([^&']))*')"

		elementcontentchar = ur'\t|\r|\n|[\u0020-\u0025]|[\u0028-\u003b]|[\u003d-\u007a]|\u007c|[\u007e-\u007F]'
		quotattrcontentchar = ur'\t|\r|\n|[\u0020-\u0021]|[\u0023-\u0025]|[\u0027-\u003b]|[\u003d-\u007a]|\u007c|[\u007e-\u007F]'
		aposattrcontentchar = ur'\t|\r|\n|[\u0020-\u0025]|[\u0028-\u003b]|[\u003d-\u007a]|\u007c|[\u007e-\u007F]'


		# CHAR elements - fix the above elementcontentchar, quotattrcontentchar, aposattrcontentchar
		#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]

		flags = re.DOTALL | re.MULTILINE | re.UNICODE

		def operator_root_callback(lexer, match, ctx):
			yield match.start(), Operator, match.group(1)
			# transition to root always - don't pop off stack
			ctx.stack = ['root']
			ctx.pos = match.end()

		def popstate_tag_callback(lexer, match, ctx):
			yield match.start(), Name.Tag, match.group(1)
			#print ctx.stack
			#print lexer.xquery_parse_state
			ctx.stack.append(lexer.xquery_parse_state.pop())
			#print lexer.xquery_parse_state
			#print ctx.stack
			ctx.pos = match.end()

		def popstate_callback(lexer, match, ctx):
			yield match.start(), Punctuation, match.group(1)
			#print ctx.stack
			ctx.stack.append(lexer.xquery_parse_state.pop())
			#print lexer.xquery_parse_state
			#print ctx.stack
			ctx.pos = match.end()

		def pushstate_starttag_callback(lexer, match, ctx):
			yield match.start(), Name.Tag, match.group(1)
			lexer.xquery_parse_state.append(ctx.state.pop)
			ctx.stack.append('start_tag')
			ctx.pos = match.end()

		def pushstate_operator_kindtest_callback(lexer, match, ctx):
			yield match.start(), Keyword, match.group(1)
			yield match.start(), Text, match.group(2)
			yield match.start(), Punctuation, match.group(3)
			#print lexer.xquery_parse_state
			lexer.xquery_parse_state.append('operator')
			#print lexer.xquery_parse_state
			#print ctx.stack
			ctx.stack.append('kindtest')
			#print ctx.stack
			ctx.pos = match.end()

		def pushstate_occurrenceindicator_kindtest_callback(lexer, match, ctx):
			yield match.start(), Name.Tag, match.group(1)
			yield match.start(), Text, match.group(2)
			yield match.start(), Punctuation, match.group(3)
			#print lexer.xquery_parse_state
			lexer.xquery_parse_state.append('occurrenceindicator')
			#print lexer.xquery_parse_state
			#print ctx.stack
			ctx.stack.append('kindtest')
			#print ctx.stack
			ctx.pos = match.end()

		def pushstate_operator_starttag_callback(lexer, match, ctx):
			yield match.start(), Name.Tag, match.group(1)
			#print lexer.xquery_parse_state
			lexer.xquery_parse_state.append('operator')
			#print lexer.xquery_parse_state
			#print ctx.stack
			ctx.stack.append('start_tag')
			#print ctx.stack
			ctx.pos = match.end()

		def pushstate_operator_root_callback(lexer, match, ctx):
			yield match.start(), Punctuation, match.group(1)
			#print lexer.xquery_parse_state
			lexer.xquery_parse_state.append('operator')
			#print lexer.xquery_parse_state
			ctx.stack = ['root']
			ctx.pos = match.end()

		def pushstate_root_callback(lexer, match, ctx):
			yield match.start(), Punctuation, match.group(1)
			cur_state = ctx.stack.pop()
			#print lexer.xquery_parse_state
			lexer.xquery_parse_state.append(cur_state)
			#print lexer.xquery_parse_state
			ctx.stack = ['root']
			ctx.pos = match.end()

		def pushstate_operator_callback(lexer, match, ctx):
			yield match.start(), Keyword, match.group(1)
			yield match.start(), Text, match.group(2)
			yield match.start(), Punctuation, match.group(3)
			#print lexer.xquery_parse_state
			lexer.xquery_parse_state.append('operator')
			#print lexer.xquery_parse_state
			#print ctx.stack
			ctx.pos = match.end()

		tokens = {
				'comment': [
            # xquery comments
						(r'(:\))', Comment, '#pop'),
						(r'(\(:)', Comment, '#push'),
						(r'[^:)]', Comment),
						(r'([^:)]|:|\))', Comment),
				],
				'whitespace': [
						(r'\s+', Text)
						],
				'operator': [
						include('whitespace'),
						(r'(\})', popstate_callback),
						(r'\(:', Comment, 'comment'),

						(r'(\{)', pushstate_root_callback),
						(r'then|else|external|and|at|div|except', Keyword, 'root'),
						(r'(eq|ge|gt|le|lt|ne|idiv|intersect|in)(?=\b)', Operator, 'root'),
						(r'is|mod|order\s+by|stable\s+order\s+by|or', Operator, 'root'),
						(r'return|satisfies|to|union|where|preserve\s+strip', Operator, 'root'),
            (r'(;|>=|>>|>|\[|<=|<<|<|-|\*|!=|\+|//|/|\||:=|\,|=)', operator_root_callback),
						(r'(castable|cast)(\s+)(as)', bygroups(Keyword, Text, Keyword), 'singletype'),
						(r'(instance)(\s+)(of)|(treat)(\s+)(as)', bygroups(Keyword, Text, Keyword), 'itemtype'),
						(r'(case)|(as)', Keyword, 'itemtype'),
						(r'(\))(\s*)(as)', bygroups(Punctuation, Text, Keyword), 'itemtype'),
						(r'\$', Name.Variable, 'varname'),
						(r'(for|let)(\s+)(\$)', bygroups(Keyword, Text, Name.Variable), 'varname'),
						#(r'\)|\?|\]', Punctuation, '#push'),
						(r'\)|\?|\]', Punctuation),
						(r'(empty)(\s+)(greatest|least)', bygroups(Keyword, Text, Keyword)),
						(r'ascending|descending|default', Keyword, '#push'),
						(r'collation', Keyword, 'uritooperator'),
						# finally catch all string literals and stay in operator state
						(stringdouble, String.Double),
						(stringsingle, String.Single),

						(r'(catch)(\s*)', bygroups(Keyword, Text), 'root'),
						],
				'uritooperator': [
						(stringdouble, String.Double, '#pop'),
						(stringsingle, String.Single, '#pop')
						],
				'namespacedecl': [
						include('whitespace'),
						(r'\(:', Comment, 'comment'),
						(r'(at)(\s+)'+stringdouble, bygroups(Keyword, Text, String.Double)),
						(r"(at)(\s+)"+stringsingle, bygroups(Keyword, Text, String.Single)),
						(stringdouble, String.Double),
						(stringsingle, String.Single),
						(r',', Punctuation),
						(r'=', Operator),
						(r';', Punctuation, 'root'),
						(ncname, Name.Namespace),
						],
				'namespacekeyword': [
						include('whitespace'),
						(r'\(:', Comment, 'comment'),
						(stringdouble, String.Double, 'namespacedecl'),
						(stringsingle, String.Single, 'namespacedecl'),
						(r'inherit|no-inherit', Keyword, 'root'),
						(r'namespace', Keyword, 'namespacedecl'),
						(r'(default)(\s+)(element)', bygroups(Keyword, Text, Keyword)),
						(r'preserve|no-preserve', Keyword),
						(r',', Punctuation)
						],
				'varname': [
						(r'\(:', Comment, 'comment'),
						(qname, Name.Variable, 'operator'),
						],
				'singletype': [
						(r'\(:', Comment, 'comment'),
						(ncname + r'(:\*)', Name.Variable, 'operator'),
						(qname, Name.Variable, 'operator'),
						],
				'itemtype': [
						include('whitespace'),
						(r'\(:', Comment, 'comment'),
						(r'\$', Punctuation, 'varname'),
						(r'void\s*\(\s*\)', bygroups(Keyword, Text, Punctuation, Text, Punctuation), 'operator'),
						(r'(element|attribute|schema-element|schema-attribute|comment|text|node|binary|document-node)(\s*)(\()', pushstate_occurrenceindicator_kindtest_callback),
						# Marklogic specific type?
						(r'(processing-instruction)(\s*)(\()', bygroups(Keyword, Text, Punctuation), ('occurrenceindicator', 'kindtestforpi')),
						(r'(item)(\s*)(\()(\s*)(\))', bygroups(Keyword, Text, Punctuation, Text, Punctuation), 'occurrenceindicator'),
						(r'\(\#', Punctuation, 'pragma'),
						(r';', Punctuation, '#pop'),
						(r'then|else', Keyword, '#pop'),
						(r'(at)(\s+)' + stringdouble, bygroups(Keyword, Text, String.Double), 'namespacedecl'),
						(r'(at)(\s+)' + stringsingle, bygroups(Keyword, Text, String.Single), 'namespacedecl'),
						(r'external|and|at|div|except|eq|ge|gt|le|lt|ne|:=|=|,|>=|>>|>|idiv|intersect|in|is|\[|\(|<=|<<|<|-|mod|!=|or|return|satisfies|to|union|\||where', Operator, 'root'),
						(r'(stable)(\s+)(order)(\s+)(by)', bygroups(Keyword, Text, Keyword, Text, Keyword), 'root'),
						(r'(castable|cast)(\s+)(as)', bygroups(Keyword, Text, Keyword), 'singletype'),
						(r'(instance)(\s+)(of)|(treat)(\s+)(as)', bygroups(Keyword, Text, Keyword), 'itemtype'),
						(r'case|as', Keyword, 'itemtype'),
						(r'(\))(\s*)(as)', bygroups(Operator, Text, Keyword), 'itemtype'),
						(ncname + r'(:\*)', Keyword.Type, 'operator'),
						(qname, Keyword.Type, 'operator'),
						],
				'kindtest': [
						(r'\(:', Comment, 'comment'),
						(r'({)', Punctuation, 'root'),
						(r'\)', Punctuation, '#pop'),
						(r'\*|' + qname, Name, 'closekindtest'),
						(r'(element|schema-element)(\s*)(\()', bygroups(Keyword, Text, Punctuation), 'kindtest')
						],
				'kindtestforpi': [
						(r'\(:', Comment, 'comment'),
						(r'\)', Punctuation, '#pop'),
						(ncname, bygroups(Name.Variable, Name.Variable)),
						(stringdouble, String.Double),
						(stringsingle, String.Single)
						],
				'closekindtest': [
						(r'\(:', Comment, 'comment'),
						(r'\)', Punctuation, '#pop'),
						(r',', Punctuation),
						(r'\{', Punctuation, ('operator', 'root')),
						(r'\?', Punctuation)
						],
				'xml_comment': [
						(r'-->', Punctuation, '#pop'),
						(r'[^-]{1,2}', Literal)
#						(r'\u009|\u00A|\u00D|[\u0020-\u00D7FF]|[\u00E000-\u00FFFD]|[\u0010000-\u0010FFFF]', Literal)
						],
				'processing_instruction': [
						(r'\s+', Text, 'processing_instruction_content'),
						(r'\?>', Punctuation, '#pop'),
						(pitarget, Name)
						],
				'processing_instruction_content': [
						(r'\?>', Punctuation, '#pop'),
						(r'\u009|\u00A|\u00D|[\u0020-\uD7FF]|[\uE000-\uFFFD]|[\u10000-\u10FFFF]', Literal)
						],
				'cdata_section': [
						(r']]>', Punctuation, '#pop'),
						(r'\u009|\u00A|\u00D|[\u0020-\uD7FF]|[\uE000-\uFFFD]|[\u10000-\u10FFFF]', Literal)
						],
				'start_tag': [
						include('whitespace'),
						(r'/>', popstate_tag_callback),
						(r'>', Name.Tag, 'element_content'),
						(r'"', Punctuation, 'quot_attribute_content'),
						(r"'", Punctuation, 'apos_attribute_content'),
						(r'=', Operator),
						(qname, Name.Tag),
						],
				'quot_attribute_content': [
						(r'"', Punctuation, 'start_tag'),
						(r'\{', Punctuation, 'root'),
						(r'""', Name.Attribute),
						(quotattrcontentchar, Name.Attribute),
						(entityref, Name.Attribute),
						(charref, Name.Attribute),
						(r'\{\{|\}\}', Name.Attribute)
						],
				'apos_attribute_content': [
						(r"'", Punctuation, 'start_tag'),
						(r'\{', Punctuation, 'root'),
						(r"''", Name.Attribute),
						(aposattrcontentchar, Name.Attribute),
						(entityref, Name.Attribute),
						(charref, Name.Attribute),
						(r'\{\{|\}\}', Name.Attribute)
						],
				'element_content': [
						(r'</', Name.Tag, 'end_tag'),
						(r'(\{)', pushstate_root_callback),
						(r'<!--', Punctuation, 'xml_comment'),
						(r'<\?', Punctuation, 'processing_instruction'),
						(r'<!\[CDATA\[', Punctuation, 'cdata_section'),
						(r'<', Name.Tag, 'start_tag'),
						(elementcontentchar, Literal),
						(entityref, Literal),
						(charref, Literal),
						(r'\{\{|\}\}', Literal),
						],
				'end_tag': [
						include('whitespace'),
						(r'(>)', popstate_tag_callback),
						(qname, Name.Tag)
						],
				'xmlspace_decl': [
						(r'\(:', Comment, 'comment'),
						(r'preserve|strip', Keyword, '#pop')
						],
				'declareordering': [
						(r'\(:', Comment, 'comment'),
						include('whitespace'),
						(r'ordered|unordered', Keyword, '#pop')
						],
				'xqueryversion': [
						include('whitespace'),
						(r'\(:', Comment, 'comment'),
						(stringdouble, String.Double),
						(stringsingle, String.Single),
						(r'encoding', Keyword),
						(r';', Punctuation, '#pop')
						],
				'pragma': [
						(qname, Name.Variable, 'pragmacontents')
						],
				'pragmacontents': [
						(r'#\)', Punctuation, 'operator'),
						(r'\u009|\u00A|\u00D|[\u0020-\u00D7FF]|[\u00E000-\u00FFFD]|[\u0010000-\u0010FFFF]', Literal),
						(r'(\s*)', Text)
						],
				'occurrenceindicator': [
						include('whitespace'),
						(r'\*|\?|\+', Operator, '#pop'),
						(r':=', Keyword, 'root'),
						],
				'option': [
						include('whitespace'),
						(qname, Name.Variable, '#pop')
						],
				'qname_braren': [
						(r'(\s*)(\(|\{)', bygroups(Text, Punctuation), 'root'),
						],
				'element_qname': [
						(qname, Name, 'root'),
						],
				'attribute_qname': [
						(qname, Name.Attribute, 'root'),
						],
        'root': [
						# TESTED
						include('whitespace'),
						(r'\(:', Comment, 'comment'),

						# END OF TESTED TRANSITIONS

						# handle operator state
						# order on numbers matters - handle most complex first
						(r'\d+(\.\d*)?[eE][\+\-]?\d+', Number.Double, 'operator'),
						(r'(\.\d+)[eE][\+\-]?\d+', Number.Double, 'operator'),
						(r'(\.\d+|\d+\.\d*)', Number, 'operator'),
						(r'(\d+)', Number.Integer, 'operator'),
						(r'(\.\.|\.|\)|\*)', Punctuation, 'operator'),
						(r'(declare)(\s+)(construction)', bygroups(Keyword, Text, Keyword), 'operator'),
						(r'(declare)(\s+)(default)(\s+)(order)', bygroups(Keyword, Text, Keyword, Text, Keyword), 'operator'),
						(ncname + ':\*', Name, 'operator'),
						(stringdouble, String.Double, 'operator'),
						(stringsingle, String.Single, 'operator'),


						(r'(\})', popstate_callback),

						#NAMESPACE DECL
						(r'declare\s+default\s+collation|declare\s+namespace|module\s+namespace|declare\s+base-uri', Name.Namespace, 'namespacedecl'),

						#NAMESPACE KEYWORD
						(r'(declare)(\s+)(default)(\s+)(element|function)', bygroups(Keyword, Text, Keyword, Text, Keyword), 'namespacekeyword'),
						(r'(import)(\s+)(schema|module)', bygroups(Keyword.Psuedo, Text, Keyword.Psuedo), 'namespacekeyword'),
						(r'(declare)(\s+)(copy-namespaces)', bygroups(Keyword, Text, Keyword), 'namespacekeyword'),


						#VARNAMEs
						(r'(for|let|some|every)(\s+)(\$)', bygroups(Keyword, Text, Name.Variable), 'varname'),
						(r'\$', Name.Variable, 'varname'),
						(r'(declare)(\s+)(variable)(\s+)(\$)', bygroups(Keyword, Text, Keyword, Text, Name.Variable), 'varname'),

						#ITEMTYPE
						(r'(\))(\s+)(as)', bygroups(Operator, Text, Keyword), 'itemtype'),

						(r'(element|attribute|schema-element|schema-attribute|comment|text|node|document-node)(\s+)(\()', pushstate_operator_kindtest_callback),

						(r'(processing-instruction)(\s+)(\()', bygroups(Keyword, Text, Operator), ('operator', 'kindtestforpi')),

						(r'<!--', Comment, ('operator', 'xml_comment')),

						(r'<\?', Operator, ('operator', 'processing_instruction')),

						(r'<!\[CDATA\[', Operator, ('operator', 'cdata_section')),

						(r'</', Name.Tag, 'end_tag'),
						(r'(<)', pushstate_operator_starttag_callback),

						(r'(declare)(\s+)(boundary-space)', bygroups(Keyword, Text, Keyword), 'xmlspace_decl'),
						(r'(validate)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), ('operator', 'root')),
						(r'(validate)(\s+)(lex|strict)', bygroups(Keyword, Text, Keyword), ('operator', 'root')),
						(r'(typeswitch)(\s*)(\()', bygroups(Keyword, Text, Punctuation)),
						(r'(element)(\s*)(\{)', bygroups(Keyword, Text, Punctuation)),
						(r'(attribute)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), ('operator', 'root')),

						(r'(document)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), 'operator'),
						(r'(text)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), 'operator'),
						(r'(processing-instruction)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), 'operator'),
						(r'(comment)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), 'operator'),
						#ATTRIBUTE
						(r'(attribute)(\s+)(?=' + qname + r')', bygroups(Keyword, Text), 'attribute_qname'),
						#ELEMENT
						(r'(element)(\s+)(?=' +qname+ r')', bygroups(Keyword, Text), 'element_qname'),
						#PROCESSING_INSTRUCTION
						(r'(processing-instruction)(\s+)' + ncname + r'(\s*)(\{)', bygroups(Keyword, Text, Name.Variable, Text, Punctuation), 'operator'),

						(r'(declare)(\s+)(function)', bygroups(Keyword, Text, Keyword)),

						(r'(\{)', pushstate_operator_root_callback),

						(r'(ordered)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), ('operator', 'root')),
						(r'(unordered)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), ('operator', 'root')),

						(r'(declare)(\s+)(ordering)', bygroups(Keyword, Text, Keyword), 'declareordering'),

						(r'(xquery)(\s+)(version)', bygroups(Keyword.Psuedo, Text, Keyword.Psuedo), 'xqueryversion'),

						(r'(\(#)', Punctuation, 'pragma'),

						(r'(declare)(\s+)(option)', bygroups(Keyword, Text, Keyword), 'option'),

						#URI LITERALS - single and double quoted
						(r'(at)(\s+)('+stringdouble+')', String.Double, 'namespacedecl'),
						(r'(at)(\s+)('+stringsingle+')', String.Single, 'namespacedecl'),


						(r'(ancestor-or-self|ancestor|attribute|child|descendant-or-self)(\s*)(::)', bygroups(Keyword, Text, Punctuation)),
						(r'(descendant|following-sibling|following|parent|preceding-sibling|preceding|self)(\s*)(::)', bygroups(Keyword, Text, Punctuation)),

						(r'(if)(\s*)(\()', bygroups(Keyword, Text, Punctuation)),

						(r'then|else', Keyword),

						# ML specific
						(r'(try)(\s*)', bygroups(Keyword, Text), 'root'),
						(r'(catch)(\s*)(\()(\$)', bygroups(Keyword, Text, Punctuation, Name.Variable), 'varname'),

						(r'//|/|\+|-|\@|;|,|\(|\)', Punctuation),

						# STANDALONE QNAMES
						(qname + r'(?=\s*[{])', Name.Variable, 'qname_braren'),
						(qname + r'(?=\s*[(])', Name.Function, 'qname_braren'),
						(qname, Name.Variable, 'operator'),
        ]
    }
