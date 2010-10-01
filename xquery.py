# -*- coding: utf-8 -*-
"""
    pygments.lexers.xquery
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    Lexer for xquery language.

    :copyright: Copyright 2010 by Steve Spigarelli
    :license: BSD, see LICENSE for details.
"""

import re

from pygments.lexer import Lexer, RegexLexer, bygroups, include, do_insertions
from pygments.token import Text, Comment, Operator, Keyword, Name, \
     String, Number, Punctuation, Literal, Generic
from pygments.lexers.web import XmlLexer


__all__ = ['XQueryLexer']


class XQueryLexer(RegexLexer):
		"""
		An XQuery lexer, parsing a stream and outputting the tokens
		needed to highlight xquery code.
		"""
		name = 'XQuery'
		aliases = ['xquery', 'xqy']
		filenames = ['*.xqy', '*.xquery']
		mimetypes = ['text/xquery', 'application/xquery']

# FIX UNICODE LATER
		#ncnamestartchar = ur"[A-Z]|_|[a-z]|[\u00C0-\u00D6]|[\u00D8-\u00F6]|[\u00F8-\u02FF]|[\u0370-\u037D]|[\u037F-\u1FFF]|[\u200C-\u200D]|[\u2070-\u218F]|[\u2C00-\u2FEF]|[\u3001-\uD7FF]|[\uF900-\uFDCF]|[\uFDF0-\uFFFD]|[\u10000-\uEFFFF]"
		ncnamestartchar = r"[A-Z]|_|[a-z]"
# FIX UNICODE LATER
		#ncnamechar = ncnamestartchar + ur"|-|\.|[0-9]|\u00B7|[\u0300-\u036F]|[\u203F-\u2040]"
		ncnamechar = ncnamestartchar + r"|-|\.|[0-9]"
		ncname = "(%s)+(%s)*" % (ncnamestartchar, ncnamechar)
		pitarget_namestartchar = r"[A-KN-WY-Z]|_|:|[a-kn-wy-z]"
		pitarget_namechar = pitarget_namestartchar + r"|-|\.|[0-9]"
		pitarget = "(%s)+(%s)*" % (pitarget_namestartchar, pitarget_namechar)
		prefixedname = "%s:%s" % (ncname, ncname)
		unprefixedname = ncname
		qname = "(%s)|(%s)" %(prefixedname, unprefixedname)

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
						include('pop-states'),
						(r'\(:', Comment, ('#pop', 'comment')),

						(r'\{', Operator, ('operator', '#push')),
						(r'then|else|external|and|at|div|except', Operator, 'root'),
						(r'eq|ge|gt|le|lt|ne|idiv|intersect|in', Operator, 'root'),
						(r'is|mod|order\s+by|stable\s+order\s+by|or', Operator, 'root'),
						(r'return|satisfies|to|union|where|preserve\s+strip', Operator, ('#pop', 'root')),
            (r';|>=|>>|>|\[|<=|<<|<|-|\*|!=|\+//|/|\||:=|\,|=', Operator, ('#pop', 'root')),
						(r'(castable|cast)(\s+)(as)', bygroups(Keyword, Text, Keyword), 'singletype'),
						(r'(instance)(\s+)(of)|(treat)(\s+)(as)|(case)|(as)|(\))(\s*)(as)', bygroups(Keyword, Text, Keyword), 'itemtype'),
						(r'\$', Name.Variable, 'varname'),
						(r'(for|let)(\s+)(\$)', bygroups(Keyword, Text, Name.Variable), 'varname'),
						(r'\)|\?|\]', Punctuation, '#push'),
						(r'(empty)(\s+)(greatest|least)', bygroups(Keyword, Text, Keyword), '#push'),
						(r'ascending|descending|default', Keyword, '#push'),
						(r'collation', Keyword, 'uritooperator'),
						# finally catch all string literals and stay in operator state
						(stringdouble, String.Double),
						(stringsingle, String.Single)

						],
				'uritooperator': [
						(stringdouble, String.Double, '#pop'),
						(stringsingle, String.Single, '#pop')
						],
				'namespacedecl': [
						include('whitespace'),
						(r'\(:', Comment, ('#pop', 'comment')),
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
						(r'\(:', Comment, ('#pop', 'comment')),
						(stringdouble, String.Double, 'namespacedecl'),
						(stringsingle, String.Single, 'namespacedecl'),
						(r'inherit|no-inherit', Keyword, 'root'),
						(r'namespace', Keyword, 'namespacedecl'),
						(r'(default)(\s+)(element)', bygroups(Keyword, Text, Keyword)),
						(r'preserve|no-preserve', Keyword),
						(r',', Punctuation)
						],
				'varname': [
						(r'\(:', Comment, ('#pop', 'comment')),
						(qname, Name.Variable, ('#pop', 'operator')),
						],
				'singletype': [
						(r'\(:', Comment, ('#pop', 'comment')),
						(ncname + r'(:\*)', Name.Class, 'operator'),
						(qname, Name.Class, 'operator'),
						],
				'itemtype': [
						(r'\(:', Comment, ('#pop', 'comment')),
						(r'\$', Punctuation, 'varname'),
						(r'void\s*\(\s*\)', bygroups(Keyword, Text, Punctuation, Text, Punctuation), 'operator'),
						(ncname + r'(:\*)', Name.Class, 'operator'),
						(qname, Name.Class, 'operator'),
						(r'(element)(\s*)(\()', bygroups(Keyword, Text, Punctuation), ('occurrenceindicator', 'kindtest')),
						(r'(attribute)(\s*)(\()', bygroups(Keyword, Text, Punctuation), ('occurrenceindicator', 'kindtest')),
						(r'(schema-element)(\s*)(\()', bygroups(Keyword, Text, Punctuation), ('occurrenceindicator', 'kindtest')),
						(r'(schema-attribute)(\s*)(\()', bygroups(Keyword, Text, Punctuation), ('occurrenceindicator', 'kindtest')),
						(r'(comment)(\s*)(\()', bygroups(Keyword, Text, Punctuation), ('occurrenceindicator', 'kindtest')),
						(r'(text)(\s*)(\()', bygroups(Keyword, Text, Punctuation), ('occurrenceindicator', 'kindtest')),
						(r'(node)(\s*)(\()', bygroups(Keyword, Text, Punctuation), ('occurrenceindicator', 'kindtest')),
						(r'(document-node)(\s*)(\()', bygroups(Keyword, Text, Punctuation), ('occurrenceindicator', 'kindtest')),
						(r'(processing-instruction)(\s*)(\()', bygroups(Keyword, Text, Punctuation), ('occurrenceindicator', 'kindtestforpi')),
						(r'(item)(\s*)(\()(\s*)(\))', bygroups(Keyword, Text, Punctuation, Text, Punctuation), 'occurrenceindicator'),
						(r'\(\#', Punctuation, 'pragma'),
						(r';', Punctuation, '#pop'),
						(r'then|else', Keyword, '#pop'),
						(r'(at)(\s+)' + stringdouble, bygroups(Keyword, Text, String.Double), 'namespacedecl'),
						(r'(at)(\s+)' + stringsingle, bygroups(Keyword, Text, String.Single), 'namespacedecl'),
						(r'external|and|at|div|except|eq|ge|gt|le|lt|ne|:=|=|,|>=|>>|>|idiv|intersect|in|is|\[|\(|<=|<<|<|-|mod|!=|or|return|satisfies|to|union|\||where', Keyword, '#pop'),
						(r'(stable)(\s+)(order)(\s+)(by)', bygroups(Keyword, Text, Keyword, Text, Keyword), 'root'),
						(r'(castable|cast)(\s+)(as)', bygroups(Keyword, Text, Keyword), 'singletype'),
						(r'(instance)(\s+)(of)|(treat)(\s+)(as)', bygroups(Keyword, Text, Keyword), 'itemtype'),
						(r'case|as', Keyword, 'itemtype'),
						(r'(\))(\s*)(as)', bygroups(Operator, Text, Keyword), 'itemtype')
						],
				'kindtest': [
						(r'\(:', Comment, ('#pop', 'comment')),
						(r'{', Punctuation, ('operator', 'root')),
						(r'\)', Punctuation, '#pop'),
						(r'\*', Name, 'closekindtest'),
						(ncname + r'(:\*)', Name.Class, 'closekindtest'),
						(qname, bygroups(Name, Name, Name, Name, Name), 'closekindtest'),
						(r'(element|schema-element)(\s*)(\()', bygroups(Keyword, Text, Punctuation), ('kindtest'))
						],
				'kindtestforpi': [
						(r'\(:', Comment, ('#pop', 'comment')),
						(r'\)', Punctuation, '#pop'),
						(ncname, bygroups(Name.Variable, Name.Variable)),
						(stringdouble, String.Double),
						(stringsingle, String.Single)
						],
				'closekindtest': [
						(r'\(:', Comment, ('#pop', 'comment')),
						include('pop-states'),
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
						(r'/>', Name.Tag, '#pop'),
						(r'>', Name.Tag, ('#pop', 'element_content')),
						(r'"', Name.Attribute, 'quot_attribute_content'),
						(r"'", Name.Attribute, 'apos_attribute_content'),
						(r'=', Operator),
						(qname, Name.Tag),
						(r'\s*', Text)
						],
				'quot_attribute_content': [
						(r'"', Punctuation, 'start_tag'),
						(r'\{', Punctuation, 'root'),
						(r'""', Literal),
						(quotattrcontentchar, Literal),
						(entityref, Literal),
						(charref, Literal),
						(r'\{\{|\}\}', Literal)
						],
				'apos_attribute_content': [
						(r"'", Punctuation, 'start_tag'),
						(r'\{', Punctuation, 'root'),
						(r"''", Literal),
						(aposattrcontentchar, Literal),
						(entityref, Literal),
						(charref, Literal),
						(r'\{\{|\}\}', Literal)
						],
				'element_content': [
						(r'</', Name.Tag, ('#pop', 'end_tag')),
						(r'\{', Punctuation, 'root'),
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
						(r'>', Name.Tag, '#pop'),
						(r'\s', Text),
						(qname, Name.Tag)
						],
				'xmlspace_decl': [
						(r'\(:', Comment, ('#pop', 'comment')),
						(r'preserve|strip', Keyword, '#pop')
						],
				'declareordering': [
						(r'\(:', Comment, ('#pop', 'comment')),
						include('whitespace'),
						(r'ordered|unordered', Keyword, '#pop')
						],
				'xqueryversion': [
						include('whitespace'),
						(r'\(:', Comment, ('#pop', 'comment')),
						(stringdouble, String.Double),
						(stringsingle, String.Single),
						(r'encoding', Keyword),
						(r';', Punctuation, '#pop')
						],
				'pragma': [
						(qname, Name, 'pragmacontents')
						],
				'pragmacontents': [
						(r'#\)', Punctuation, 'operator'),
						(r'\u009|\u00A|\u00D|[\u0020-\u00D7FF]|[\u00E000-\u00FFFD]|[\u0010000-\u0010FFFF]', Literal),
						(r'(\s*)', Text)
						],
				'occurrenceindicator': [
						(r'', Text, '#pop')
						],
				'option': [
						(qname, Name, 'root')
						],
				'pop-states': [
						(r'\}', Punctuation, '#pop'),
						(r'\)', Punctuation, '#pop')
						],
				'qname_braren': [
						(r'(\s*)(\(|\{)', bygroups(Text, Punctuation), ('#pop', 'operator', 'root')),
						],
        'root': [
						include('pop-states'),
						include('whitespace'),
						(r'\(:', Comment, 'comment'),

						# handle operator state
						(r'(\.\d+|\d+\.\d*)', Operator, 'operator'),
						(r'(\.\.|\.|\)|\*)', Operator, 'operator'),
						(r'(declare)(\s+)(construction)', bygroups(Operator, Text, Operator), 'operator'),
						(r'(declare)(\s+)(default)(\s+)(order)', bygroups(Operator, Text, Operator, Text, Operator), 'operator'),
						(r'(\d+)(\.\d*)?(\s*)([eE])(\s*)([\+\-]?)(\s*)(\d+)', bygroups(Operator, Operator, Text, Operator, Text, Operator, Text, Operator), 'operator'),
						(r'(\.\d+)(\s*)([eE])(\s*)([\+\-]?)(\s*)(\d+)', bygroups(Operator, Text, Operator, Text, Operator, Text, Operator), 'operator'),
						(r'(\d+)', Operator, 'operator'),
						(ncname + ':\*', Name, 'operator'),
						(stringdouble, String.Double, 'operator'),
						(stringsingle, String.Single, 'operator'),

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

						(r'(element)(\s+)(\()|(attribute)(\s+)(\()|(schema-element)(\s+)(\()|(schema-attribute)(\s+)(\()|(comment)(\s+)(\()|(text)(\s+)(\()|(node)(\s+)(\()|(document-node)(\s+)(\()', bygroups(Keyword, Text, Operator), ('operator', 'kindtest')),

						(r'(processing-instruction)(\s+)(\()', bygroups(Keyword, Text, Operator), ('operator', 'kindtestforpi')),

						(r'<!--', Comment, ('operator', 'xml_comment')),

						(r'<\?', Operator, ('operator', 'processing_instruction')),

						(r'<!\[CDATA\[', Operator, ('operator', 'cdata_section')),

						(r'<', Name.Tag, ('operator', 'start_tag')),

						(r'(declare)(\s+)(boundary-space)', bygroups(Keyword, Text, Keyword), 'xmlspace_decl'),
						(r'(validate)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), ('operator', '#push')),
						(r'(validate)(\s+)(lex|strict)', bygroups(Keyword, Text, Keyword), ('operator', '#push')),
						(r'(typeswitch)(\s*)(\()', bygroups(Keyword, Text, Punctuation)),
						(r'(element)(\s*)(\{)', bygroups(Keyword, Text, Punctuation)),
						(r'(attribute)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), ('operator', '#push')),

						(r'(document)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), 'operator'),
						(r'(text)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), 'operator'),
						(r'(processing-instruction)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), 'operator'),
						(r'(comment)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), 'operator'),
						#ATTRIBUTE
						(r'(attribute)(\s+)' + qname + r'(\s*)(\{)', bygroups(Keyword, Text, Name.Variable, Text, Punctuation), 'operator'),
						#ELEMENT
						(r'(element)(\s+)(?=' +qname+ r')', bygroups(Keyword, Text)),
						#PROCESSING_INSTRUCTION
						(r'(processing-instruction)(\s+)' + ncname + r'(\s*)(\{)', bygroups(Keyword, Text, Name.Variable, Text, Punctuation), 'operator'),

						(r'(declare)(\s+)(function)', bygroups(Keyword, Text, Keyword)),

						(r'\{', Punctuation, ('operator', '#push')),

						(r'(ordered)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), ('operator', '#push')),
						(r'(unordered)(\s*)(\{)', bygroups(Keyword, Text, Punctuation), ('operator', '#push')),

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
						(r'//|/|\+|-|\@|;|,|\(', Punctuation),

						# STANDALONE QNAMES
						(qname + r'(?=((\s*)(\(|\{)))', Name.Variable, 'qname_braren'),
						(qname, Name, 'operator'),
        ]
    }
