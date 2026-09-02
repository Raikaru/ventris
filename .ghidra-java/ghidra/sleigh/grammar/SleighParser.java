package ghidra.sleigh.grammar;
// $ANTLR 3.5.2 ghidra/sleigh/grammar/SleighParser.g 2026-08-17 17:23:47

import org.antlr.runtime.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import org.antlr.runtime.tree.*;


@SuppressWarnings("all")
public class SleighParser extends AbstractSleighParser {
	public static final String[] tokenNames = new String[] {
		"<invalid>", "<EOR>", "<DOWN>", "<UP>", "ALPHA", "ALPHAUP", "AMPERSAND", 
		"ASSIGN", "ASTERISK", "BINDIGIT", "BIN_INT", "BOOL_AND", "BOOL_OR", "BOOL_XOR", 
		"CARET", "COLON", "COMMA", "CPPCOMMENT", "DEC_INT", "DIGIT", "DISPCHAR", 
		"ELLIPSIS", "EOL", "EQUAL", "ESCAPE", "EXCLAIM", "FDIV", "FEQUAL", "FGREAT", 
		"FGREATEQUAL", "FLESS", "FLESSEQUAL", "FMINUS", "FMULT", "FNOTEQUAL", 
		"FPLUS", "GREAT", "GREATEQUAL", "HEXDIGIT", "HEX_INT", "IDENTIFIER", "KEY_ALIGNMENT", 
		"KEY_ATTACH", "KEY_BIG", "KEY_BITRANGE", "KEY_BUILD", "KEY_CALL", "KEY_CONTEXT", 
		"KEY_CROSSBUILD", "KEY_DEC", "KEY_DEFAULT", "KEY_DEFINE", "KEY_ENDIAN", 
		"KEY_EXPORT", "KEY_GOTO", "KEY_HEX", "KEY_LITTLE", "KEY_LOCAL", "KEY_MACRO", 
		"KEY_NAMES", "KEY_NOFLOW", "KEY_OFFSET", "KEY_PCODEOP", "KEY_RETURN", 
		"KEY_SIGNED", "KEY_SIZE", "KEY_SPACE", "KEY_TOKEN", "KEY_TYPE", "KEY_UNIMPL", 
		"KEY_VALUES", "KEY_VARIABLES", "KEY_WORDSIZE", "LBRACE", "LBRACKET", "LEFT", 
		"LESS", "LESSEQUAL", "LINECOMMENT", "LPAREN", "MINUS", "NOTEQUAL", "OCTAL_ESCAPE", 
		"OP_ADD", "OP_ADDRESS_OF", "OP_ALIGNMENT", "OP_AND", "OP_APPLY", "OP_ARGUMENTS", 
		"OP_ASSIGN", "OP_BIG", "OP_BIN_CONSTANT", "OP_BITRANGE", "OP_BITRANGE2", 
		"OP_BITRANGES", "OP_BIT_PATTERN", "OP_BOOL_AND", "OP_BOOL_OR", "OP_BOOL_XOR", 
		"OP_BUILD", "OP_CALL", "OP_CONCATENATE", "OP_CONSTRUCTOR", "OP_CONTEXT", 
		"OP_CONTEXT_BLOCK", "OP_CROSSBUILD", "OP_CTLIST", "OP_DEC", "OP_DECLARATIVE_SIZE", 
		"OP_DEC_CONSTANT", "OP_DEFAULT", "OP_DEREFERENCE", "OP_DISPLAY", "OP_DIV", 
		"OP_ELLIPSIS", "OP_ELLIPSIS_RIGHT", "OP_EMPTY_LIST", "OP_ENDIAN", "OP_EQUAL", 
		"OP_EXPORT", "OP_FADD", "OP_FDIV", "OP_FEQUAL", "OP_FGREAT", "OP_FGREATEQUAL", 
		"OP_FIELDDEF", "OP_FIELDDEFS", "OP_FIELD_MODS", "OP_FLESS", "OP_FLESSEQUAL", 
		"OP_FMULT", "OP_FNEGATE", "OP_FNOTEQUAL", "OP_FSUB", "OP_GOTO", "OP_GREAT", 
		"OP_GREATEQUAL", "OP_HEX", "OP_HEX_CONSTANT", "OP_IDENTIFIER", "OP_IDENTIFIER_LIST", 
		"OP_IF", "OP_INTBLIST", "OP_INVERT", "OP_JUMPDEST_ABSOLUTE", "OP_JUMPDEST_DYNAMIC", 
		"OP_JUMPDEST_LABEL", "OP_JUMPDEST_RELATIVE", "OP_JUMPDEST_SYMBOL", "OP_LABEL", 
		"OP_LEFT", "OP_LESS", "OP_LESSEQUAL", "OP_LITTLE", "OP_LOCAL", "OP_MACRO", 
		"OP_MULT", "OP_NAMES", "OP_NEGATE", "OP_NIL", "OP_NOFLOW", "OP_NOP", "OP_NOT", 
		"OP_NOTEQUAL", "OP_NOT_DEFAULT", "OP_NO_CONTEXT_BLOCK", "OP_NO_FIELD_MOD", 
		"OP_OR", "OP_PARENTHESIZED", "OP_PCODE", "OP_PCODEOP", "OP_QSTRING", "OP_REM", 
		"OP_RETURN", "OP_RIGHT", "OP_SDIV", "OP_SECTION_LABEL", "OP_SEMANTIC", 
		"OP_SEQUENCE", "OP_SGREAT", "OP_SGREATEQUAL", "OP_SIGNED", "OP_SIZE", 
		"OP_SIZING_SIZE", "OP_SLESS", "OP_SLESSEQUAL", "OP_SPACE", "OP_SPACEMODS", 
		"OP_SREM", "OP_SRIGHT", "OP_STRING", "OP_STRING_OR_IDENT_LIST", "OP_SUB", 
		"OP_SUBTABLE", "OP_TABLE", "OP_TOKEN", "OP_TOKEN_ENDIAN", "OP_TRUNCATION_SIZE", 
		"OP_TYPE", "OP_UNIMPL", "OP_VALUES", "OP_VARIABLES", "OP_VARNODE", "OP_WHITESPACE", 
		"OP_WILDCARD", "OP_WITH", "OP_WORDSIZE", "OP_XOR", "PERCENT", "PIPE", 
		"PLUS", "PP_ESCAPE", "PP_POSITION", "QSTRING", "RBRACE", "RBRACKET", "RES_IF", 
		"RES_IS", "RES_WITH", "RIGHT", "RPAREN", "SDIV", "SEMI", "SGREAT", "SGREATEQUAL", 
		"SLASH", "SLESS", "SLESSEQUAL", "SPEC_AND", "SPEC_OR", "SPEC_XOR", "SREM", 
		"SRIGHT", "TILDE", "Tokens", "UNDERSCORE", "UNICODE_ESCAPE", "UNKNOWN", 
		"WS", "239", "240", "241", "242", "243", "244", "245", "246", "247", "248", 
		"249", "250", "251", "252", "253", "254", "255", "256", "257", "258", 
		"259", "260", "261", "262", "263", "264", "265", "266", "267", "268", 
		"269", "270", "271", "272", "273", "274", "275", "276", "277", "278", 
		"279", "280", "281", "282", "283", "284", "285", "286", "287", "288", 
		"289", "290", "291", "292", "293", "294", "295", "296", "297", "298", 
		"299", "300", "301", "302", "303", "304", "305", "306"
	};
	public static final int EOF=-1;
	public static final int ALPHA=4;
	public static final int ALPHAUP=5;
	public static final int AMPERSAND=6;
	public static final int ASSIGN=7;
	public static final int ASTERISK=8;
	public static final int BINDIGIT=9;
	public static final int BIN_INT=10;
	public static final int BOOL_AND=11;
	public static final int BOOL_OR=12;
	public static final int BOOL_XOR=13;
	public static final int CARET=14;
	public static final int COLON=15;
	public static final int COMMA=16;
	public static final int CPPCOMMENT=17;
	public static final int DEC_INT=18;
	public static final int DIGIT=19;
	public static final int DISPCHAR=20;
	public static final int ELLIPSIS=21;
	public static final int EOL=22;
	public static final int EQUAL=23;
	public static final int ESCAPE=24;
	public static final int EXCLAIM=25;
	public static final int FDIV=26;
	public static final int FEQUAL=27;
	public static final int FGREAT=28;
	public static final int FGREATEQUAL=29;
	public static final int FLESS=30;
	public static final int FLESSEQUAL=31;
	public static final int FMINUS=32;
	public static final int FMULT=33;
	public static final int FNOTEQUAL=34;
	public static final int FPLUS=35;
	public static final int GREAT=36;
	public static final int GREATEQUAL=37;
	public static final int HEXDIGIT=38;
	public static final int HEX_INT=39;
	public static final int IDENTIFIER=40;
	public static final int KEY_ALIGNMENT=41;
	public static final int KEY_ATTACH=42;
	public static final int KEY_BIG=43;
	public static final int KEY_BITRANGE=44;
	public static final int KEY_BUILD=45;
	public static final int KEY_CALL=46;
	public static final int KEY_CONTEXT=47;
	public static final int KEY_CROSSBUILD=48;
	public static final int KEY_DEC=49;
	public static final int KEY_DEFAULT=50;
	public static final int KEY_DEFINE=51;
	public static final int KEY_ENDIAN=52;
	public static final int KEY_EXPORT=53;
	public static final int KEY_GOTO=54;
	public static final int KEY_HEX=55;
	public static final int KEY_LITTLE=56;
	public static final int KEY_LOCAL=57;
	public static final int KEY_MACRO=58;
	public static final int KEY_NAMES=59;
	public static final int KEY_NOFLOW=60;
	public static final int KEY_OFFSET=61;
	public static final int KEY_PCODEOP=62;
	public static final int KEY_RETURN=63;
	public static final int KEY_SIGNED=64;
	public static final int KEY_SIZE=65;
	public static final int KEY_SPACE=66;
	public static final int KEY_TOKEN=67;
	public static final int KEY_TYPE=68;
	public static final int KEY_UNIMPL=69;
	public static final int KEY_VALUES=70;
	public static final int KEY_VARIABLES=71;
	public static final int KEY_WORDSIZE=72;
	public static final int LBRACE=73;
	public static final int LBRACKET=74;
	public static final int LEFT=75;
	public static final int LESS=76;
	public static final int LESSEQUAL=77;
	public static final int LINECOMMENT=78;
	public static final int LPAREN=79;
	public static final int MINUS=80;
	public static final int NOTEQUAL=81;
	public static final int OCTAL_ESCAPE=82;
	public static final int OP_ADD=83;
	public static final int OP_ADDRESS_OF=84;
	public static final int OP_ALIGNMENT=85;
	public static final int OP_AND=86;
	public static final int OP_APPLY=87;
	public static final int OP_ARGUMENTS=88;
	public static final int OP_ASSIGN=89;
	public static final int OP_BIG=90;
	public static final int OP_BIN_CONSTANT=91;
	public static final int OP_BITRANGE=92;
	public static final int OP_BITRANGE2=93;
	public static final int OP_BITRANGES=94;
	public static final int OP_BIT_PATTERN=95;
	public static final int OP_BOOL_AND=96;
	public static final int OP_BOOL_OR=97;
	public static final int OP_BOOL_XOR=98;
	public static final int OP_BUILD=99;
	public static final int OP_CALL=100;
	public static final int OP_CONCATENATE=101;
	public static final int OP_CONSTRUCTOR=102;
	public static final int OP_CONTEXT=103;
	public static final int OP_CONTEXT_BLOCK=104;
	public static final int OP_CROSSBUILD=105;
	public static final int OP_CTLIST=106;
	public static final int OP_DEC=107;
	public static final int OP_DECLARATIVE_SIZE=108;
	public static final int OP_DEC_CONSTANT=109;
	public static final int OP_DEFAULT=110;
	public static final int OP_DEREFERENCE=111;
	public static final int OP_DISPLAY=112;
	public static final int OP_DIV=113;
	public static final int OP_ELLIPSIS=114;
	public static final int OP_ELLIPSIS_RIGHT=115;
	public static final int OP_EMPTY_LIST=116;
	public static final int OP_ENDIAN=117;
	public static final int OP_EQUAL=118;
	public static final int OP_EXPORT=119;
	public static final int OP_FADD=120;
	public static final int OP_FDIV=121;
	public static final int OP_FEQUAL=122;
	public static final int OP_FGREAT=123;
	public static final int OP_FGREATEQUAL=124;
	public static final int OP_FIELDDEF=125;
	public static final int OP_FIELDDEFS=126;
	public static final int OP_FIELD_MODS=127;
	public static final int OP_FLESS=128;
	public static final int OP_FLESSEQUAL=129;
	public static final int OP_FMULT=130;
	public static final int OP_FNEGATE=131;
	public static final int OP_FNOTEQUAL=132;
	public static final int OP_FSUB=133;
	public static final int OP_GOTO=134;
	public static final int OP_GREAT=135;
	public static final int OP_GREATEQUAL=136;
	public static final int OP_HEX=137;
	public static final int OP_HEX_CONSTANT=138;
	public static final int OP_IDENTIFIER=139;
	public static final int OP_IDENTIFIER_LIST=140;
	public static final int OP_IF=141;
	public static final int OP_INTBLIST=142;
	public static final int OP_INVERT=143;
	public static final int OP_JUMPDEST_ABSOLUTE=144;
	public static final int OP_JUMPDEST_DYNAMIC=145;
	public static final int OP_JUMPDEST_LABEL=146;
	public static final int OP_JUMPDEST_RELATIVE=147;
	public static final int OP_JUMPDEST_SYMBOL=148;
	public static final int OP_LABEL=149;
	public static final int OP_LEFT=150;
	public static final int OP_LESS=151;
	public static final int OP_LESSEQUAL=152;
	public static final int OP_LITTLE=153;
	public static final int OP_LOCAL=154;
	public static final int OP_MACRO=155;
	public static final int OP_MULT=156;
	public static final int OP_NAMES=157;
	public static final int OP_NEGATE=158;
	public static final int OP_NIL=159;
	public static final int OP_NOFLOW=160;
	public static final int OP_NOP=161;
	public static final int OP_NOT=162;
	public static final int OP_NOTEQUAL=163;
	public static final int OP_NOT_DEFAULT=164;
	public static final int OP_NO_CONTEXT_BLOCK=165;
	public static final int OP_NO_FIELD_MOD=166;
	public static final int OP_OR=167;
	public static final int OP_PARENTHESIZED=168;
	public static final int OP_PCODE=169;
	public static final int OP_PCODEOP=170;
	public static final int OP_QSTRING=171;
	public static final int OP_REM=172;
	public static final int OP_RETURN=173;
	public static final int OP_RIGHT=174;
	public static final int OP_SDIV=175;
	public static final int OP_SECTION_LABEL=176;
	public static final int OP_SEMANTIC=177;
	public static final int OP_SEQUENCE=178;
	public static final int OP_SGREAT=179;
	public static final int OP_SGREATEQUAL=180;
	public static final int OP_SIGNED=181;
	public static final int OP_SIZE=182;
	public static final int OP_SIZING_SIZE=183;
	public static final int OP_SLESS=184;
	public static final int OP_SLESSEQUAL=185;
	public static final int OP_SPACE=186;
	public static final int OP_SPACEMODS=187;
	public static final int OP_SREM=188;
	public static final int OP_SRIGHT=189;
	public static final int OP_STRING=190;
	public static final int OP_STRING_OR_IDENT_LIST=191;
	public static final int OP_SUB=192;
	public static final int OP_SUBTABLE=193;
	public static final int OP_TABLE=194;
	public static final int OP_TOKEN=195;
	public static final int OP_TOKEN_ENDIAN=196;
	public static final int OP_TRUNCATION_SIZE=197;
	public static final int OP_TYPE=198;
	public static final int OP_UNIMPL=199;
	public static final int OP_VALUES=200;
	public static final int OP_VARIABLES=201;
	public static final int OP_VARNODE=202;
	public static final int OP_WHITESPACE=203;
	public static final int OP_WILDCARD=204;
	public static final int OP_WITH=205;
	public static final int OP_WORDSIZE=206;
	public static final int OP_XOR=207;
	public static final int PERCENT=208;
	public static final int PIPE=209;
	public static final int PLUS=210;
	public static final int PP_ESCAPE=211;
	public static final int PP_POSITION=212;
	public static final int QSTRING=213;
	public static final int RBRACE=214;
	public static final int RBRACKET=215;
	public static final int RES_IF=216;
	public static final int RES_IS=217;
	public static final int RES_WITH=218;
	public static final int RIGHT=219;
	public static final int RPAREN=220;
	public static final int SDIV=221;
	public static final int SEMI=222;
	public static final int SGREAT=223;
	public static final int SGREATEQUAL=224;
	public static final int SLASH=225;
	public static final int SLESS=226;
	public static final int SLESSEQUAL=227;
	public static final int SPEC_AND=228;
	public static final int SPEC_OR=229;
	public static final int SPEC_XOR=230;
	public static final int SREM=231;
	public static final int SRIGHT=232;
	public static final int TILDE=233;
	public static final int Tokens=234;
	public static final int UNDERSCORE=235;
	public static final int UNICODE_ESCAPE=236;
	public static final int UNKNOWN=237;
	public static final int WS=238;

	// delegates
	public SleighParser_DisplayParser gDisplayParser;
	public SleighParser_SemanticParser gSemanticParser;
	public AbstractSleighParser[] getDelegates() {
		return new AbstractSleighParser[] {gDisplayParser, gSemanticParser};
	}

	// delegators


	public SleighParser(TokenStream input) {
		this(input, new RecognizerSharedState());
	}
	public SleighParser(TokenStream input, RecognizerSharedState state) {
		super(input, state);
		gDisplayParser = new SleighParser_DisplayParser(input, state, this);
		gSemanticParser = new SleighParser_SemanticParser(input, state, this);
	}

	protected TreeAdaptor adaptor = new CommonTreeAdaptor();

	public void setTreeAdaptor(TreeAdaptor adaptor) {
		this.adaptor = adaptor;
		gDisplayParser.setTreeAdaptor(this.adaptor);gSemanticParser.setTreeAdaptor(this.adaptor);
	}
	public TreeAdaptor getTreeAdaptor() {
		return adaptor;
	}
	@Override public String[] getTokenNames() { return SleighParser.tokenNames; }
	@Override public String getGrammarFileName() { return "ghidra/sleigh/grammar/SleighParser.g"; }


		@Override
		public void setLexer(SleighLexer lexer) {
			super.setLexer(lexer);
			gDisplayParser.setLexer(lexer);
			gSemanticParser.setLexer(lexer);
		}

		@Override
		public void setEnv(ParsingEnvironment env) {
			super.setEnv(env);
			gDisplayParser.setEnv(env);
			gSemanticParser.setEnv(env);
		}


	public static class spec_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "spec"
	// ghidra/sleigh/grammar/SleighParser.g:32:1: spec : endiandef ( definition | constructorlike )* EOF ;
	public final SleighParser.spec_return spec() throws RecognitionException {
		SleighParser.spec_return retval = new SleighParser.spec_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token EOF4=null;
		ParserRuleReturnScope endiandef1 =null;
		ParserRuleReturnScope definition2 =null;
		ParserRuleReturnScope constructorlike3 =null;

		CommonTree EOF4_tree=null;

		try {
			// ghidra/sleigh/grammar/SleighParser.g:38:2: ( endiandef ( definition | constructorlike )* EOF )
			// ghidra/sleigh/grammar/SleighParser.g:38:4: endiandef ( definition | constructorlike )* EOF
			{
			root_0 = (CommonTree)adaptor.nil();


			if ( state.backtracking==0 ) {
						if (env.getLexingErrors() > 0) {
							bail("Abort");
						}
					}
			pushFollow(FOLLOW_endiandef_in_spec78);
			endiandef1=endiandef();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, endiandef1.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:44:3: ( definition | constructorlike )*
			loop1:
			while (true) {
				int alt1=3;
				switch ( input.LA(1) ) {
				case KEY_DEFINE:
					{
					int LA1_2 = input.LA(2);
					if ( ((LA1_2 >= IDENTIFIER && LA1_2 <= KEY_WORDSIZE)) ) {
						alt1=1;
					}
					else if ( (LA1_2==COLON) ) {
						alt1=2;
					}

					}
					break;
				case KEY_ATTACH:
					{
					int LA1_3 = input.LA(2);
					if ( (LA1_3==KEY_NAMES||(LA1_3 >= KEY_VALUES && LA1_3 <= KEY_VARIABLES)) ) {
						alt1=1;
					}
					else if ( (LA1_3==COLON) ) {
						alt1=2;
					}

					}
					break;
				case COLON:
				case IDENTIFIER:
				case KEY_ALIGNMENT:
				case KEY_BIG:
				case KEY_BITRANGE:
				case KEY_BUILD:
				case KEY_CALL:
				case KEY_CONTEXT:
				case KEY_CROSSBUILD:
				case KEY_DEC:
				case KEY_DEFAULT:
				case KEY_ENDIAN:
				case KEY_EXPORT:
				case KEY_GOTO:
				case KEY_HEX:
				case KEY_LITTLE:
				case KEY_LOCAL:
				case KEY_MACRO:
				case KEY_NAMES:
				case KEY_NOFLOW:
				case KEY_OFFSET:
				case KEY_PCODEOP:
				case KEY_RETURN:
				case KEY_SIGNED:
				case KEY_SIZE:
				case KEY_SPACE:
				case KEY_TOKEN:
				case KEY_TYPE:
				case KEY_UNIMPL:
				case KEY_VALUES:
				case KEY_VARIABLES:
				case KEY_WORDSIZE:
				case RES_WITH:
					{
					alt1=2;
					}
					break;
				}
				switch (alt1) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:44:5: definition
					{
					pushFollow(FOLLOW_definition_in_spec84);
					definition2=definition();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, definition2.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:45:5: constructorlike
					{
					pushFollow(FOLLOW_constructorlike_in_spec90);
					constructorlike3=constructorlike();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, constructorlike3.getTree());

					}
					break;

				default :
					break loop1;
				}
			}

			EOF4=(Token)match(input,EOF,FOLLOW_EOF_in_spec97); if (state.failed) return retval;
			if ( state.backtracking==0 ) {
			EOF4_tree = (CommonTree)adaptor.create(EOF4);
			adaptor.addChild(root_0, EOF4_tree);
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
			if ( state.backtracking==0 ) {
					if (env.getParsingErrors() > 0) {
						bail("Abort");
					}
				}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "spec"


	public static class endiandef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "endiandef"
	// ghidra/sleigh/grammar/SleighParser.g:49:1: endiandef : lc= KEY_DEFINE KEY_ENDIAN ASSIGN endian SEMI -> ^( OP_ENDIAN[$lc,\"define endian\"] endian ) ;
	public final SleighParser.endiandef_return endiandef() throws RecognitionException {
		SleighParser.endiandef_return retval = new SleighParser.endiandef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token KEY_ENDIAN5=null;
		Token ASSIGN6=null;
		Token SEMI8=null;
		ParserRuleReturnScope endian7 =null;

		CommonTree lc_tree=null;
		CommonTree KEY_ENDIAN5_tree=null;
		CommonTree ASSIGN6_tree=null;
		CommonTree SEMI8_tree=null;
		RewriteRuleTokenStream stream_KEY_ENDIAN=new RewriteRuleTokenStream(adaptor,"token KEY_ENDIAN");
		RewriteRuleTokenStream stream_SEMI=new RewriteRuleTokenStream(adaptor,"token SEMI");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_endian=new RewriteRuleSubtreeStream(adaptor,"rule endian");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:50:2: (lc= KEY_DEFINE KEY_ENDIAN ASSIGN endian SEMI -> ^( OP_ENDIAN[$lc,\"define endian\"] endian ) )
			// ghidra/sleigh/grammar/SleighParser.g:50:4: lc= KEY_DEFINE KEY_ENDIAN ASSIGN endian SEMI
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_endiandef110); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			KEY_ENDIAN5=(Token)match(input,KEY_ENDIAN,FOLLOW_KEY_ENDIAN_in_endiandef112); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_ENDIAN.add(KEY_ENDIAN5);

			ASSIGN6=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_endiandef114); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN6);

			pushFollow(FOLLOW_endian_in_endiandef116);
			endian7=endian();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_endian.add(endian7.getTree());
			SEMI8=(Token)match(input,SEMI,FOLLOW_SEMI_in_endiandef118); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_SEMI.add(SEMI8);

			// AST REWRITE
			// elements: endian
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 50:48: -> ^( OP_ENDIAN[$lc,\"define endian\"] endian )
			{
				// ghidra/sleigh/grammar/SleighParser.g:50:51: ^( OP_ENDIAN[$lc,\"define endian\"] endian )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ENDIAN, lc, "define endian"), root_1);
				adaptor.addChild(root_1, stream_endian.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "endiandef"


	public static class endian_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "endian"
	// ghidra/sleigh/grammar/SleighParser.g:53:1: endian : (lc= KEY_BIG -> OP_BIG[$lc] |lc= KEY_LITTLE -> OP_LITTLE[$lc] );
	public final SleighParser.endian_return endian() throws RecognitionException {
		SleighParser.endian_return retval = new SleighParser.endian_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_BIG=new RewriteRuleTokenStream(adaptor,"token KEY_BIG");
		RewriteRuleTokenStream stream_KEY_LITTLE=new RewriteRuleTokenStream(adaptor,"token KEY_LITTLE");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:54:2: (lc= KEY_BIG -> OP_BIG[$lc] |lc= KEY_LITTLE -> OP_LITTLE[$lc] )
			int alt2=2;
			int LA2_0 = input.LA(1);
			if ( (LA2_0==KEY_BIG) ) {
				alt2=1;
			}
			else if ( (LA2_0==KEY_LITTLE) ) {
				alt2=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 2, 0, input);
				throw nvae;
			}

			switch (alt2) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:54:4: lc= KEY_BIG
					{
					lc=(Token)match(input,KEY_BIG,FOLLOW_KEY_BIG_in_endian140); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_BIG.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 54:15: -> OP_BIG[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_BIG, lc));
					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:55:4: lc= KEY_LITTLE
					{
					lc=(Token)match(input,KEY_LITTLE,FOLLOW_KEY_LITTLE_in_endian152); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_LITTLE.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 55:18: -> OP_LITTLE[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_LITTLE, lc));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "endian"


	public static class definition_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "definition"
	// ghidra/sleigh/grammar/SleighParser.g:58:1: definition : ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach ) SEMI !;
	public final SleighParser.definition_return definition() throws RecognitionException {
		SleighParser.definition_return retval = new SleighParser.definition_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token SEMI19=null;
		ParserRuleReturnScope aligndef9 =null;
		ParserRuleReturnScope tokendef10 =null;
		ParserRuleReturnScope contextdef11 =null;
		ParserRuleReturnScope spacedef12 =null;
		ParserRuleReturnScope varnodedef13 =null;
		ParserRuleReturnScope bitrangedef14 =null;
		ParserRuleReturnScope pcodeopdef15 =null;
		ParserRuleReturnScope valueattach16 =null;
		ParserRuleReturnScope nameattach17 =null;
		ParserRuleReturnScope varattach18 =null;

		CommonTree SEMI19_tree=null;

		try {
			// ghidra/sleigh/grammar/SleighParser.g:59:2: ( ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach ) SEMI !)
			// ghidra/sleigh/grammar/SleighParser.g:59:4: ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach ) SEMI !
			{
			root_0 = (CommonTree)adaptor.nil();


			// ghidra/sleigh/grammar/SleighParser.g:59:4: ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach )
			int alt3=10;
			int LA3_0 = input.LA(1);
			if ( (LA3_0==KEY_DEFINE) ) {
				switch ( input.LA(2) ) {
				case KEY_ALIGNMENT:
					{
					int LA3_3 = input.LA(3);
					if ( (LA3_3==ASSIGN) ) {
						alt3=1;
					}
					else if ( (LA3_3==KEY_OFFSET) ) {
						alt3=5;
					}

					else {
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 3, 3, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_TOKEN:
					{
					int LA3_4 = input.LA(3);
					if ( ((LA3_4 >= IDENTIFIER && LA3_4 <= KEY_NOFLOW)||(LA3_4 >= KEY_PCODEOP && LA3_4 <= KEY_WORDSIZE)) ) {
						alt3=2;
					}
					else if ( (LA3_4==KEY_OFFSET) ) {
						int LA3_15 = input.LA(4);
						if ( (LA3_15==ASSIGN) ) {
							alt3=5;
						}
						else if ( (LA3_15==LPAREN) ) {
							alt3=2;
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 3, 15, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 3, 4, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_CONTEXT:
					{
					int LA3_5 = input.LA(3);
					if ( ((LA3_5 >= IDENTIFIER && LA3_5 <= KEY_NOFLOW)||(LA3_5 >= KEY_PCODEOP && LA3_5 <= KEY_WORDSIZE)) ) {
						alt3=3;
					}
					else if ( (LA3_5==KEY_OFFSET) ) {
						int LA3_17 = input.LA(4);
						if ( (LA3_17==ASSIGN) ) {
							alt3=5;
						}
						else if ( ((LA3_17 >= IDENTIFIER && LA3_17 <= KEY_WORDSIZE)||LA3_17==SEMI) ) {
							alt3=3;
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 3, 17, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 3, 5, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_SPACE:
					{
					int LA3_6 = input.LA(3);
					if ( ((LA3_6 >= IDENTIFIER && LA3_6 <= KEY_NOFLOW)||(LA3_6 >= KEY_PCODEOP && LA3_6 <= KEY_WORDSIZE)) ) {
						alt3=4;
					}
					else if ( (LA3_6==KEY_OFFSET) ) {
						int LA3_19 = input.LA(4);
						if ( (LA3_19==ASSIGN) ) {
							alt3=5;
						}
						else if ( (LA3_19==KEY_DEFAULT||LA3_19==KEY_SIZE||LA3_19==KEY_TYPE||LA3_19==KEY_WORDSIZE||LA3_19==SEMI) ) {
							alt3=4;
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 3, 19, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 3, 6, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_BITRANGE:
					{
					int LA3_7 = input.LA(3);
					if ( ((LA3_7 >= IDENTIFIER && LA3_7 <= KEY_NOFLOW)||(LA3_7 >= KEY_PCODEOP && LA3_7 <= KEY_WORDSIZE)) ) {
						alt3=6;
					}
					else if ( (LA3_7==KEY_OFFSET) ) {
						int LA3_21 = input.LA(4);
						if ( (LA3_21==ASSIGN) ) {
							int LA3_24 = input.LA(5);
							if ( (LA3_24==BIN_INT||LA3_24==DEC_INT||LA3_24==HEX_INT) ) {
								alt3=5;
							}
							else if ( ((LA3_24 >= IDENTIFIER && LA3_24 <= KEY_WORDSIZE)) ) {
								alt3=6;
							}

							else {
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 3, 24, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 3, 21, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 3, 7, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_PCODEOP:
					{
					int LA3_8 = input.LA(3);
					if ( ((LA3_8 >= IDENTIFIER && LA3_8 <= KEY_NOFLOW)||(LA3_8 >= KEY_PCODEOP && LA3_8 <= KEY_WORDSIZE)||LA3_8==LBRACKET||LA3_8==UNDERSCORE) ) {
						alt3=7;
					}
					else if ( (LA3_8==KEY_OFFSET) ) {
						int LA3_23 = input.LA(4);
						if ( (LA3_23==ASSIGN) ) {
							alt3=5;
						}
						else if ( (LA3_23==SEMI) ) {
							alt3=7;
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 3, 23, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 3, 8, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case IDENTIFIER:
				case KEY_ATTACH:
				case KEY_BIG:
				case KEY_BUILD:
				case KEY_CALL:
				case KEY_CROSSBUILD:
				case KEY_DEC:
				case KEY_DEFAULT:
				case KEY_DEFINE:
				case KEY_ENDIAN:
				case KEY_EXPORT:
				case KEY_GOTO:
				case KEY_HEX:
				case KEY_LITTLE:
				case KEY_LOCAL:
				case KEY_MACRO:
				case KEY_NAMES:
				case KEY_NOFLOW:
				case KEY_OFFSET:
				case KEY_RETURN:
				case KEY_SIGNED:
				case KEY_SIZE:
				case KEY_TYPE:
				case KEY_UNIMPL:
				case KEY_VALUES:
				case KEY_VARIABLES:
				case KEY_WORDSIZE:
					{
					alt3=5;
					}
					break;
				default:
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 3, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
			}
			else if ( (LA3_0==KEY_ATTACH) ) {
				switch ( input.LA(2) ) {
				case KEY_VALUES:
					{
					alt3=8;
					}
					break;
				case KEY_NAMES:
					{
					alt3=9;
					}
					break;
				case KEY_VARIABLES:
					{
					alt3=10;
					}
					break;
				default:
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 3, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 3, 0, input);
				throw nvae;
			}

			switch (alt3) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:59:5: aligndef
					{
					pushFollow(FOLLOW_aligndef_in_definition169);
					aligndef9=aligndef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, aligndef9.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:60:4: tokendef
					{
					pushFollow(FOLLOW_tokendef_in_definition174);
					tokendef10=tokendef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, tokendef10.getTree());

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:61:4: contextdef
					{
					pushFollow(FOLLOW_contextdef_in_definition179);
					contextdef11=contextdef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, contextdef11.getTree());

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighParser.g:62:4: spacedef
					{
					pushFollow(FOLLOW_spacedef_in_definition184);
					spacedef12=spacedef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, spacedef12.getTree());

					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighParser.g:63:4: varnodedef
					{
					pushFollow(FOLLOW_varnodedef_in_definition189);
					varnodedef13=varnodedef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, varnodedef13.getTree());

					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighParser.g:64:4: bitrangedef
					{
					pushFollow(FOLLOW_bitrangedef_in_definition194);
					bitrangedef14=bitrangedef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, bitrangedef14.getTree());

					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighParser.g:65:4: pcodeopdef
					{
					pushFollow(FOLLOW_pcodeopdef_in_definition199);
					pcodeopdef15=pcodeopdef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pcodeopdef15.getTree());

					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighParser.g:66:4: valueattach
					{
					pushFollow(FOLLOW_valueattach_in_definition204);
					valueattach16=valueattach();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, valueattach16.getTree());

					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighParser.g:67:4: nameattach
					{
					pushFollow(FOLLOW_nameattach_in_definition209);
					nameattach17=nameattach();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, nameattach17.getTree());

					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighParser.g:68:4: varattach
					{
					pushFollow(FOLLOW_varattach_in_definition214);
					varattach18=varattach();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, varattach18.getTree());

					}
					break;

			}

			SEMI19=(Token)match(input,SEMI,FOLLOW_SEMI_in_definition217); if (state.failed) return retval;
			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "definition"


	public static class aligndef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "aligndef"
	// ghidra/sleigh/grammar/SleighParser.g:71:1: aligndef : lc= KEY_DEFINE KEY_ALIGNMENT ASSIGN integer -> ^( OP_ALIGNMENT[$lc, \"define alignment\"] integer ) ;
	public final SleighParser.aligndef_return aligndef() throws RecognitionException {
		SleighParser.aligndef_return retval = new SleighParser.aligndef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token KEY_ALIGNMENT20=null;
		Token ASSIGN21=null;
		ParserRuleReturnScope integer22 =null;

		CommonTree lc_tree=null;
		CommonTree KEY_ALIGNMENT20_tree=null;
		CommonTree ASSIGN21_tree=null;
		RewriteRuleTokenStream stream_KEY_ALIGNMENT=new RewriteRuleTokenStream(adaptor,"token KEY_ALIGNMENT");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:72:2: (lc= KEY_DEFINE KEY_ALIGNMENT ASSIGN integer -> ^( OP_ALIGNMENT[$lc, \"define alignment\"] integer ) )
			// ghidra/sleigh/grammar/SleighParser.g:72:4: lc= KEY_DEFINE KEY_ALIGNMENT ASSIGN integer
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_aligndef231); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			KEY_ALIGNMENT20=(Token)match(input,KEY_ALIGNMENT,FOLLOW_KEY_ALIGNMENT_in_aligndef233); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_ALIGNMENT.add(KEY_ALIGNMENT20);

			ASSIGN21=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_aligndef235); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN21);

			pushFollow(FOLLOW_integer_in_aligndef237);
			integer22=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(integer22.getTree());
			// AST REWRITE
			// elements: integer
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 72:47: -> ^( OP_ALIGNMENT[$lc, \"define alignment\"] integer )
			{
				// ghidra/sleigh/grammar/SleighParser.g:72:50: ^( OP_ALIGNMENT[$lc, \"define alignment\"] integer )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ALIGNMENT, lc, "define alignment"), root_1);
				adaptor.addChild(root_1, stream_integer.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "aligndef"


	public static class tokendef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "tokendef"
	// ghidra/sleigh/grammar/SleighParser.g:75:1: tokendef : (lc= KEY_DEFINE KEY_TOKEN identifier LPAREN integer rp= RPAREN fielddefs[$rp] -> ^( OP_TOKEN[$lc, \"define token\"] identifier integer fielddefs ) |lc= KEY_DEFINE KEY_TOKEN identifier LPAREN integer RPAREN rp= KEY_ENDIAN ASSIGN endian fielddefs[$rp] -> ^( OP_TOKEN_ENDIAN[$lc, \"define token\"] identifier integer endian fielddefs ) );
	public final SleighParser.tokendef_return tokendef() throws RecognitionException {
		SleighParser.tokendef_return retval = new SleighParser.tokendef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		Token KEY_TOKEN23=null;
		Token LPAREN25=null;
		Token KEY_TOKEN28=null;
		Token LPAREN30=null;
		Token RPAREN32=null;
		Token ASSIGN33=null;
		ParserRuleReturnScope identifier24 =null;
		ParserRuleReturnScope integer26 =null;
		ParserRuleReturnScope fielddefs27 =null;
		ParserRuleReturnScope identifier29 =null;
		ParserRuleReturnScope integer31 =null;
		ParserRuleReturnScope endian34 =null;
		ParserRuleReturnScope fielddefs35 =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		CommonTree KEY_TOKEN23_tree=null;
		CommonTree LPAREN25_tree=null;
		CommonTree KEY_TOKEN28_tree=null;
		CommonTree LPAREN30_tree=null;
		CommonTree RPAREN32_tree=null;
		CommonTree ASSIGN33_tree=null;
		RewriteRuleTokenStream stream_KEY_TOKEN=new RewriteRuleTokenStream(adaptor,"token KEY_TOKEN");
		RewriteRuleTokenStream stream_KEY_ENDIAN=new RewriteRuleTokenStream(adaptor,"token KEY_ENDIAN");
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_fielddefs=new RewriteRuleSubtreeStream(adaptor,"rule fielddefs");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");
		RewriteRuleSubtreeStream stream_endian=new RewriteRuleSubtreeStream(adaptor,"rule endian");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:76:2: (lc= KEY_DEFINE KEY_TOKEN identifier LPAREN integer rp= RPAREN fielddefs[$rp] -> ^( OP_TOKEN[$lc, \"define token\"] identifier integer fielddefs ) |lc= KEY_DEFINE KEY_TOKEN identifier LPAREN integer RPAREN rp= KEY_ENDIAN ASSIGN endian fielddefs[$rp] -> ^( OP_TOKEN_ENDIAN[$lc, \"define token\"] identifier integer endian fielddefs ) )
			int alt4=2;
			int LA4_0 = input.LA(1);
			if ( (LA4_0==KEY_DEFINE) ) {
				int LA4_1 = input.LA(2);
				if ( (LA4_1==KEY_TOKEN) ) {
					switch ( input.LA(3) ) {
					case IDENTIFIER:
						{
						int LA4_3 = input.LA(4);
						if ( (LA4_3==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 3, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_ALIGNMENT:
						{
						int LA4_4 = input.LA(4);
						if ( (LA4_4==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 4, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_ATTACH:
						{
						int LA4_5 = input.LA(4);
						if ( (LA4_5==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 5, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_BIG:
						{
						int LA4_6 = input.LA(4);
						if ( (LA4_6==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 6, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_BITRANGE:
						{
						int LA4_7 = input.LA(4);
						if ( (LA4_7==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 7, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_BUILD:
						{
						int LA4_8 = input.LA(4);
						if ( (LA4_8==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 8, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_CALL:
						{
						int LA4_9 = input.LA(4);
						if ( (LA4_9==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 9, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_CONTEXT:
						{
						int LA4_10 = input.LA(4);
						if ( (LA4_10==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 10, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_CROSSBUILD:
						{
						int LA4_11 = input.LA(4);
						if ( (LA4_11==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 11, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_DEC:
						{
						int LA4_12 = input.LA(4);
						if ( (LA4_12==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 12, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_DEFAULT:
						{
						int LA4_13 = input.LA(4);
						if ( (LA4_13==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 13, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_DEFINE:
						{
						int LA4_14 = input.LA(4);
						if ( (LA4_14==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 14, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_ENDIAN:
						{
						int LA4_15 = input.LA(4);
						if ( (LA4_15==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 15, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_EXPORT:
						{
						int LA4_16 = input.LA(4);
						if ( (LA4_16==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 16, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_GOTO:
						{
						int LA4_17 = input.LA(4);
						if ( (LA4_17==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 17, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_HEX:
						{
						int LA4_18 = input.LA(4);
						if ( (LA4_18==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 18, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_LITTLE:
						{
						int LA4_19 = input.LA(4);
						if ( (LA4_19==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 19, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_LOCAL:
						{
						int LA4_20 = input.LA(4);
						if ( (LA4_20==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 20, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_MACRO:
						{
						int LA4_21 = input.LA(4);
						if ( (LA4_21==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 21, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_NAMES:
						{
						int LA4_22 = input.LA(4);
						if ( (LA4_22==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 22, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_NOFLOW:
						{
						int LA4_23 = input.LA(4);
						if ( (LA4_23==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 23, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_OFFSET:
						{
						int LA4_24 = input.LA(4);
						if ( (LA4_24==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 24, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_PCODEOP:
						{
						int LA4_25 = input.LA(4);
						if ( (LA4_25==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 25, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_RETURN:
						{
						int LA4_26 = input.LA(4);
						if ( (LA4_26==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 26, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_SIGNED:
						{
						int LA4_27 = input.LA(4);
						if ( (LA4_27==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 27, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_SIZE:
						{
						int LA4_28 = input.LA(4);
						if ( (LA4_28==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 28, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_SPACE:
						{
						int LA4_29 = input.LA(4);
						if ( (LA4_29==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 29, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_TOKEN:
						{
						int LA4_30 = input.LA(4);
						if ( (LA4_30==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 30, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_TYPE:
						{
						int LA4_31 = input.LA(4);
						if ( (LA4_31==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 31, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_UNIMPL:
						{
						int LA4_32 = input.LA(4);
						if ( (LA4_32==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 32, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_VALUES:
						{
						int LA4_33 = input.LA(4);
						if ( (LA4_33==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 33, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_VARIABLES:
						{
						int LA4_34 = input.LA(4);
						if ( (LA4_34==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 34, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_WORDSIZE:
						{
						int LA4_35 = input.LA(4);
						if ( (LA4_35==LPAREN) ) {
							switch ( input.LA(5) ) {
							case HEX_INT:
								{
								int LA4_37 = input.LA(6);
								if ( (LA4_37==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 37, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case DEC_INT:
								{
								int LA4_38 = input.LA(6);
								if ( (LA4_38==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 38, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							case BIN_INT:
								{
								int LA4_39 = input.LA(6);
								if ( (LA4_39==RPAREN) ) {
									int LA4_40 = input.LA(7);
									if ( (LA4_40==KEY_ENDIAN) ) {
										alt4=2;
									}
									else if ( (LA4_40==IDENTIFIER||LA4_40==SEMI) ) {
										alt4=1;
									}

									else {
										if (state.backtracking>0) {state.failed=true; return retval;}
										int nvaeMark = input.mark();
										try {
											for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
												input.consume();
											}
											NoViableAltException nvae =
												new NoViableAltException("", 4, 40, input);
											throw nvae;
										} finally {
											input.rewind(nvaeMark);
										}
									}

								}

								else {
									if (state.backtracking>0) {state.failed=true; return retval;}
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 39, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

								}
								break;
							default:
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 36, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 35, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					default:
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 4, 2, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 4, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 4, 0, input);
				throw nvae;
			}

			switch (alt4) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:76:4: lc= KEY_DEFINE KEY_TOKEN identifier LPAREN integer rp= RPAREN fielddefs[$rp]
					{
					lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_tokendef259); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

					KEY_TOKEN23=(Token)match(input,KEY_TOKEN,FOLLOW_KEY_TOKEN_in_tokendef261); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_TOKEN.add(KEY_TOKEN23);

					pushFollow(FOLLOW_identifier_in_tokendef263);
					identifier24=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_identifier.add(identifier24.getTree());
					LPAREN25=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_tokendef265); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LPAREN.add(LPAREN25);

					pushFollow(FOLLOW_integer_in_tokendef267);
					integer26=integer();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_integer.add(integer26.getTree());
					rp=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_tokendef271); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RPAREN.add(rp);

					pushFollow(FOLLOW_fielddefs_in_tokendef273);
					fielddefs27=fielddefs(rp);
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_fielddefs.add(fielddefs27.getTree());
					// AST REWRITE
					// elements: integer, fielddefs, identifier
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 76:79: -> ^( OP_TOKEN[$lc, \"define token\"] identifier integer fielddefs )
					{
						// ghidra/sleigh/grammar/SleighParser.g:76:82: ^( OP_TOKEN[$lc, \"define token\"] identifier integer fielddefs )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_TOKEN, lc, "define token"), root_1);
						adaptor.addChild(root_1, stream_identifier.nextTree());
						adaptor.addChild(root_1, stream_integer.nextTree());
						adaptor.addChild(root_1, stream_fielddefs.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:77:6: lc= KEY_DEFINE KEY_TOKEN identifier LPAREN integer RPAREN rp= KEY_ENDIAN ASSIGN endian fielddefs[$rp]
					{
					lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_tokendef296); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

					KEY_TOKEN28=(Token)match(input,KEY_TOKEN,FOLLOW_KEY_TOKEN_in_tokendef298); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_TOKEN.add(KEY_TOKEN28);

					pushFollow(FOLLOW_identifier_in_tokendef300);
					identifier29=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_identifier.add(identifier29.getTree());
					LPAREN30=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_tokendef302); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LPAREN.add(LPAREN30);

					pushFollow(FOLLOW_integer_in_tokendef304);
					integer31=integer();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_integer.add(integer31.getTree());
					RPAREN32=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_tokendef306); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RPAREN.add(RPAREN32);

					rp=(Token)match(input,KEY_ENDIAN,FOLLOW_KEY_ENDIAN_in_tokendef310); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_ENDIAN.add(rp);

					ASSIGN33=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_tokendef312); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN33);

					pushFollow(FOLLOW_endian_in_tokendef314);
					endian34=endian();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_endian.add(endian34.getTree());
					pushFollow(FOLLOW_fielddefs_in_tokendef316);
					fielddefs35=fielddefs(rp);
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_fielddefs.add(fielddefs35.getTree());
					// AST REWRITE
					// elements: identifier, fielddefs, integer, endian
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 77:106: -> ^( OP_TOKEN_ENDIAN[$lc, \"define token\"] identifier integer endian fielddefs )
					{
						// ghidra/sleigh/grammar/SleighParser.g:77:109: ^( OP_TOKEN_ENDIAN[$lc, \"define token\"] identifier integer endian fielddefs )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_TOKEN_ENDIAN, lc, "define token"), root_1);
						adaptor.addChild(root_1, stream_identifier.nextTree());
						adaptor.addChild(root_1, stream_integer.nextTree());
						adaptor.addChild(root_1, stream_endian.nextTree());
						adaptor.addChild(root_1, stream_fielddefs.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "tokendef"


	public static class fielddefs_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "fielddefs"
	// ghidra/sleigh/grammar/SleighParser.g:80:1: fielddefs[Token lc] : ( fielddef )* -> ^( OP_FIELDDEFS[lc, \"field definitions\"] ( fielddef )* ) ;
	public final SleighParser.fielddefs_return fielddefs(Token lc) throws RecognitionException {
		SleighParser.fielddefs_return retval = new SleighParser.fielddefs_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope fielddef36 =null;

		RewriteRuleSubtreeStream stream_fielddef=new RewriteRuleSubtreeStream(adaptor,"rule fielddef");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:81:2: ( ( fielddef )* -> ^( OP_FIELDDEFS[lc, \"field definitions\"] ( fielddef )* ) )
			// ghidra/sleigh/grammar/SleighParser.g:81:4: ( fielddef )*
			{
			// ghidra/sleigh/grammar/SleighParser.g:81:4: ( fielddef )*
			loop5:
			while (true) {
				int alt5=2;
				int LA5_0 = input.LA(1);
				if ( (LA5_0==IDENTIFIER) ) {
					alt5=1;
				}

				switch (alt5) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:81:4: fielddef
					{
					pushFollow(FOLLOW_fielddef_in_fielddefs344);
					fielddef36=fielddef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_fielddef.add(fielddef36.getTree());
					}
					break;

				default :
					break loop5;
				}
			}

			// AST REWRITE
			// elements: fielddef
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 81:14: -> ^( OP_FIELDDEFS[lc, \"field definitions\"] ( fielddef )* )
			{
				// ghidra/sleigh/grammar/SleighParser.g:81:17: ^( OP_FIELDDEFS[lc, \"field definitions\"] ( fielddef )* )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FIELDDEFS, lc, "field definitions"), root_1);
				// ghidra/sleigh/grammar/SleighParser.g:81:57: ( fielddef )*
				while ( stream_fielddef.hasNext() ) {
					adaptor.addChild(root_1, stream_fielddef.nextTree());
				}
				stream_fielddef.reset();

				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "fielddefs"


	public static class fielddef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "fielddef"
	// ghidra/sleigh/grammar/SleighParser.g:84:1: fielddef : strict_id lc= ASSIGN LPAREN s= integer COMMA e= integer rp= RPAREN fieldmods[$rp] -> ^( OP_FIELDDEF[$lc, \"field definition\"] strict_id $s $e fieldmods ) ;
	public final SleighParser.fielddef_return fielddef() throws RecognitionException {
		SleighParser.fielddef_return retval = new SleighParser.fielddef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		Token LPAREN38=null;
		Token COMMA39=null;
		ParserRuleReturnScope s =null;
		ParserRuleReturnScope e =null;
		ParserRuleReturnScope strict_id37 =null;
		ParserRuleReturnScope fieldmods40 =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		CommonTree LPAREN38_tree=null;
		CommonTree COMMA39_tree=null;
		RewriteRuleTokenStream stream_COMMA=new RewriteRuleTokenStream(adaptor,"token COMMA");
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_strict_id=new RewriteRuleSubtreeStream(adaptor,"rule strict_id");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");
		RewriteRuleSubtreeStream stream_fieldmods=new RewriteRuleSubtreeStream(adaptor,"rule fieldmods");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:85:2: ( strict_id lc= ASSIGN LPAREN s= integer COMMA e= integer rp= RPAREN fieldmods[$rp] -> ^( OP_FIELDDEF[$lc, \"field definition\"] strict_id $s $e fieldmods ) )
			// ghidra/sleigh/grammar/SleighParser.g:85:4: strict_id lc= ASSIGN LPAREN s= integer COMMA e= integer rp= RPAREN fieldmods[$rp]
			{
			pushFollow(FOLLOW_strict_id_in_fielddef366);
			strict_id37=strict_id();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_strict_id.add(strict_id37.getTree());
			lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_fielddef370); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(lc);

			LPAREN38=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_fielddef372); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_LPAREN.add(LPAREN38);

			pushFollow(FOLLOW_integer_in_fielddef376);
			s=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(s.getTree());
			COMMA39=(Token)match(input,COMMA,FOLLOW_COMMA_in_fielddef378); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_COMMA.add(COMMA39);

			pushFollow(FOLLOW_integer_in_fielddef382);
			e=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(e.getTree());
			rp=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_fielddef386); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RPAREN.add(rp);

			pushFollow(FOLLOW_fieldmods_in_fielddef388);
			fieldmods40=fieldmods(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_fieldmods.add(fieldmods40.getTree());
			// AST REWRITE
			// elements: s, strict_id, e, fieldmods
			// token labels: 
			// rule labels: s, e, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_s=new RewriteRuleSubtreeStream(adaptor,"rule s",s!=null?s.getTree():null);
			RewriteRuleSubtreeStream stream_e=new RewriteRuleSubtreeStream(adaptor,"rule e",e!=null?e.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 85:82: -> ^( OP_FIELDDEF[$lc, \"field definition\"] strict_id $s $e fieldmods )
			{
				// ghidra/sleigh/grammar/SleighParser.g:85:85: ^( OP_FIELDDEF[$lc, \"field definition\"] strict_id $s $e fieldmods )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FIELDDEF, lc, "field definition"), root_1);
				adaptor.addChild(root_1, stream_strict_id.nextTree());
				adaptor.addChild(root_1, stream_s.nextTree());
				adaptor.addChild(root_1, stream_e.nextTree());
				adaptor.addChild(root_1, stream_fieldmods.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "fielddef"


	public static class fieldmods_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "fieldmods"
	// ghidra/sleigh/grammar/SleighParser.g:88:1: fieldmods[Token it] : ( ( fieldmod )+ -> ^( OP_FIELD_MODS[it, \"field modifiers\"] ( fieldmod )+ ) | -> OP_NO_FIELD_MOD[it, \"<no field mod>\"] );
	public final SleighParser.fieldmods_return fieldmods(Token it) throws RecognitionException {
		SleighParser.fieldmods_return retval = new SleighParser.fieldmods_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope fieldmod41 =null;

		RewriteRuleSubtreeStream stream_fieldmod=new RewriteRuleSubtreeStream(adaptor,"rule fieldmod");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:89:2: ( ( fieldmod )+ -> ^( OP_FIELD_MODS[it, \"field modifiers\"] ( fieldmod )+ ) | -> OP_NO_FIELD_MOD[it, \"<no field mod>\"] )
			int alt7=2;
			int LA7_0 = input.LA(1);
			if ( (LA7_0==KEY_DEC||LA7_0==KEY_HEX||LA7_0==KEY_SIGNED) ) {
				alt7=1;
			}
			else if ( (LA7_0==IDENTIFIER||LA7_0==SEMI) ) {
				alt7=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 7, 0, input);
				throw nvae;
			}

			switch (alt7) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:89:4: ( fieldmod )+
					{
					// ghidra/sleigh/grammar/SleighParser.g:89:4: ( fieldmod )+
					int cnt6=0;
					loop6:
					while (true) {
						int alt6=2;
						int LA6_0 = input.LA(1);
						if ( (LA6_0==KEY_DEC||LA6_0==KEY_HEX||LA6_0==KEY_SIGNED) ) {
							alt6=1;
						}

						switch (alt6) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:89:4: fieldmod
							{
							pushFollow(FOLLOW_fieldmod_in_fieldmods418);
							fieldmod41=fieldmod();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) stream_fieldmod.add(fieldmod41.getTree());
							}
							break;

						default :
							if ( cnt6 >= 1 ) break loop6;
							if (state.backtracking>0) {state.failed=true; return retval;}
							EarlyExitException eee = new EarlyExitException(6, input);
							throw eee;
						}
						cnt6++;
					}

					// AST REWRITE
					// elements: fieldmod
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 89:14: -> ^( OP_FIELD_MODS[it, \"field modifiers\"] ( fieldmod )+ )
					{
						// ghidra/sleigh/grammar/SleighParser.g:89:17: ^( OP_FIELD_MODS[it, \"field modifiers\"] ( fieldmod )+ )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FIELD_MODS, it, "field modifiers"), root_1);
						if ( !(stream_fieldmod.hasNext()) ) {
							throw new RewriteEarlyExitException();
						}
						while ( stream_fieldmod.hasNext() ) {
							adaptor.addChild(root_1, stream_fieldmod.nextTree());
						}
						stream_fieldmod.reset();

						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:90:4: 
					{
					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 90:4: -> OP_NO_FIELD_MOD[it, \"<no field mod>\"]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_NO_FIELD_MOD, it, "<no field mod>"));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "fieldmods"


	public static class fieldmod_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "fieldmod"
	// ghidra/sleigh/grammar/SleighParser.g:93:1: fieldmod : (lc= KEY_SIGNED -> OP_SIGNED[$lc] |lc= KEY_HEX -> OP_HEX[$lc] |lc= KEY_DEC -> OP_DEC[$lc] );
	public final SleighParser.fieldmod_return fieldmod() throws RecognitionException {
		SleighParser.fieldmod_return retval = new SleighParser.fieldmod_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_DEC=new RewriteRuleTokenStream(adaptor,"token KEY_DEC");
		RewriteRuleTokenStream stream_KEY_SIGNED=new RewriteRuleTokenStream(adaptor,"token KEY_SIGNED");
		RewriteRuleTokenStream stream_KEY_HEX=new RewriteRuleTokenStream(adaptor,"token KEY_HEX");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:94:5: (lc= KEY_SIGNED -> OP_SIGNED[$lc] |lc= KEY_HEX -> OP_HEX[$lc] |lc= KEY_DEC -> OP_DEC[$lc] )
			int alt8=3;
			switch ( input.LA(1) ) {
			case KEY_SIGNED:
				{
				alt8=1;
				}
				break;
			case KEY_HEX:
				{
				alt8=2;
				}
				break;
			case KEY_DEC:
				{
				alt8=3;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 8, 0, input);
				throw nvae;
			}
			switch (alt8) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:94:9: lc= KEY_SIGNED
					{
					lc=(Token)match(input,KEY_SIGNED,FOLLOW_KEY_SIGNED_in_fieldmod455); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_SIGNED.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 94:23: -> OP_SIGNED[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_SIGNED, lc));
					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:95:9: lc= KEY_HEX
					{
					lc=(Token)match(input,KEY_HEX,FOLLOW_KEY_HEX_in_fieldmod472); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_HEX.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 95:20: -> OP_HEX[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_HEX, lc));
					}


					retval.tree = root_0;
					}

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:96:9: lc= KEY_DEC
					{
					lc=(Token)match(input,KEY_DEC,FOLLOW_KEY_DEC_in_fieldmod489); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEC.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 96:20: -> OP_DEC[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_DEC, lc));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "fieldmod"


	public static class contextfielddefs_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "contextfielddefs"
	// ghidra/sleigh/grammar/SleighParser.g:99:1: contextfielddefs[Token lc] : ( contextfielddef )* -> ^( OP_FIELDDEFS[lc, \"field definitions\"] ( contextfielddef )* ) ;
	public final SleighParser.contextfielddefs_return contextfielddefs(Token lc) throws RecognitionException {
		SleighParser.contextfielddefs_return retval = new SleighParser.contextfielddefs_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope contextfielddef42 =null;

		RewriteRuleSubtreeStream stream_contextfielddef=new RewriteRuleSubtreeStream(adaptor,"rule contextfielddef");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:100:2: ( ( contextfielddef )* -> ^( OP_FIELDDEFS[lc, \"field definitions\"] ( contextfielddef )* ) )
			// ghidra/sleigh/grammar/SleighParser.g:100:4: ( contextfielddef )*
			{
			// ghidra/sleigh/grammar/SleighParser.g:100:4: ( contextfielddef )*
			loop9:
			while (true) {
				int alt9=2;
				int LA9_0 = input.LA(1);
				if ( ((LA9_0 >= IDENTIFIER && LA9_0 <= KEY_WORDSIZE)) ) {
					alt9=1;
				}

				switch (alt9) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:100:4: contextfielddef
					{
					pushFollow(FOLLOW_contextfielddef_in_contextfielddefs509);
					contextfielddef42=contextfielddef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_contextfielddef.add(contextfielddef42.getTree());
					}
					break;

				default :
					break loop9;
				}
			}

			// AST REWRITE
			// elements: contextfielddef
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 100:21: -> ^( OP_FIELDDEFS[lc, \"field definitions\"] ( contextfielddef )* )
			{
				// ghidra/sleigh/grammar/SleighParser.g:100:24: ^( OP_FIELDDEFS[lc, \"field definitions\"] ( contextfielddef )* )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FIELDDEFS, lc, "field definitions"), root_1);
				// ghidra/sleigh/grammar/SleighParser.g:100:64: ( contextfielddef )*
				while ( stream_contextfielddef.hasNext() ) {
					adaptor.addChild(root_1, stream_contextfielddef.nextTree());
				}
				stream_contextfielddef.reset();

				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "contextfielddefs"


	public static class contextfielddef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "contextfielddef"
	// ghidra/sleigh/grammar/SleighParser.g:103:1: contextfielddef : identifier lc= ASSIGN LPAREN s= integer COMMA e= integer rp= RPAREN contextfieldmods[$rp] -> ^( OP_FIELDDEF[$lc, \"field definition\"] identifier $s $e contextfieldmods ) ;
	public final SleighParser.contextfielddef_return contextfielddef() throws RecognitionException {
		SleighParser.contextfielddef_return retval = new SleighParser.contextfielddef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		Token LPAREN44=null;
		Token COMMA45=null;
		ParserRuleReturnScope s =null;
		ParserRuleReturnScope e =null;
		ParserRuleReturnScope identifier43 =null;
		ParserRuleReturnScope contextfieldmods46 =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		CommonTree LPAREN44_tree=null;
		CommonTree COMMA45_tree=null;
		RewriteRuleTokenStream stream_COMMA=new RewriteRuleTokenStream(adaptor,"token COMMA");
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_contextfieldmods=new RewriteRuleSubtreeStream(adaptor,"rule contextfieldmods");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:104:2: ( identifier lc= ASSIGN LPAREN s= integer COMMA e= integer rp= RPAREN contextfieldmods[$rp] -> ^( OP_FIELDDEF[$lc, \"field definition\"] identifier $s $e contextfieldmods ) )
			// ghidra/sleigh/grammar/SleighParser.g:104:4: identifier lc= ASSIGN LPAREN s= integer COMMA e= integer rp= RPAREN contextfieldmods[$rp]
			{
			pushFollow(FOLLOW_identifier_in_contextfielddef531);
			identifier43=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier43.getTree());
			lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_contextfielddef535); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(lc);

			LPAREN44=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_contextfielddef537); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_LPAREN.add(LPAREN44);

			pushFollow(FOLLOW_integer_in_contextfielddef541);
			s=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(s.getTree());
			COMMA45=(Token)match(input,COMMA,FOLLOW_COMMA_in_contextfielddef543); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_COMMA.add(COMMA45);

			pushFollow(FOLLOW_integer_in_contextfielddef547);
			e=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(e.getTree());
			rp=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_contextfielddef551); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RPAREN.add(rp);

			pushFollow(FOLLOW_contextfieldmods_in_contextfielddef553);
			contextfieldmods46=contextfieldmods(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_contextfieldmods.add(contextfieldmods46.getTree());
			// AST REWRITE
			// elements: identifier, contextfieldmods, e, s
			// token labels: 
			// rule labels: s, e, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_s=new RewriteRuleSubtreeStream(adaptor,"rule s",s!=null?s.getTree():null);
			RewriteRuleSubtreeStream stream_e=new RewriteRuleSubtreeStream(adaptor,"rule e",e!=null?e.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 104:90: -> ^( OP_FIELDDEF[$lc, \"field definition\"] identifier $s $e contextfieldmods )
			{
				// ghidra/sleigh/grammar/SleighParser.g:104:93: ^( OP_FIELDDEF[$lc, \"field definition\"] identifier $s $e contextfieldmods )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FIELDDEF, lc, "field definition"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				adaptor.addChild(root_1, stream_s.nextTree());
				adaptor.addChild(root_1, stream_e.nextTree());
				adaptor.addChild(root_1, stream_contextfieldmods.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "contextfielddef"


	public static class contextfieldmods_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "contextfieldmods"
	// ghidra/sleigh/grammar/SleighParser.g:107:1: contextfieldmods[Token it] : ( ( contextfieldmod )+ -> ^( OP_FIELD_MODS[it, \"context field modifiers\"] ( contextfieldmod )+ ) | -> OP_NO_FIELD_MOD[it, \"<no field mod>\"] );
	public final SleighParser.contextfieldmods_return contextfieldmods(Token it) throws RecognitionException {
		SleighParser.contextfieldmods_return retval = new SleighParser.contextfieldmods_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope contextfieldmod47 =null;

		RewriteRuleSubtreeStream stream_contextfieldmod=new RewriteRuleSubtreeStream(adaptor,"rule contextfieldmod");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:108:5: ( ( contextfieldmod )+ -> ^( OP_FIELD_MODS[it, \"context field modifiers\"] ( contextfieldmod )+ ) | -> OP_NO_FIELD_MOD[it, \"<no field mod>\"] )
			int alt11=2;
			switch ( input.LA(1) ) {
			case KEY_SIGNED:
				{
				int LA11_1 = input.LA(2);
				if ( ((LA11_1 >= IDENTIFIER && LA11_1 <= KEY_WORDSIZE)||LA11_1==SEMI) ) {
					alt11=1;
				}
				else if ( (LA11_1==ASSIGN) ) {
					alt11=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 11, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA11_2 = input.LA(2);
				if ( ((LA11_2 >= IDENTIFIER && LA11_2 <= KEY_WORDSIZE)||LA11_2==SEMI) ) {
					alt11=1;
				}
				else if ( (LA11_2==ASSIGN) ) {
					alt11=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 11, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_HEX:
				{
				int LA11_3 = input.LA(2);
				if ( ((LA11_3 >= IDENTIFIER && LA11_3 <= KEY_WORDSIZE)||LA11_3==SEMI) ) {
					alt11=1;
				}
				else if ( (LA11_3==ASSIGN) ) {
					alt11=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 11, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEC:
				{
				int LA11_4 = input.LA(2);
				if ( ((LA11_4 >= IDENTIFIER && LA11_4 <= KEY_WORDSIZE)||LA11_4==SEMI) ) {
					alt11=1;
				}
				else if ( (LA11_4==ASSIGN) ) {
					alt11=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 11, 4, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case IDENTIFIER:
			case KEY_ALIGNMENT:
			case KEY_ATTACH:
			case KEY_BIG:
			case KEY_BITRANGE:
			case KEY_BUILD:
			case KEY_CALL:
			case KEY_CONTEXT:
			case KEY_CROSSBUILD:
			case KEY_DEFAULT:
			case KEY_DEFINE:
			case KEY_ENDIAN:
			case KEY_EXPORT:
			case KEY_GOTO:
			case KEY_LITTLE:
			case KEY_LOCAL:
			case KEY_MACRO:
			case KEY_NAMES:
			case KEY_OFFSET:
			case KEY_PCODEOP:
			case KEY_RETURN:
			case KEY_SIZE:
			case KEY_SPACE:
			case KEY_TOKEN:
			case KEY_TYPE:
			case KEY_UNIMPL:
			case KEY_VALUES:
			case KEY_VARIABLES:
			case KEY_WORDSIZE:
			case SEMI:
				{
				alt11=2;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 11, 0, input);
				throw nvae;
			}
			switch (alt11) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:108:9: ( contextfieldmod )+
					{
					// ghidra/sleigh/grammar/SleighParser.g:108:9: ( contextfieldmod )+
					int cnt10=0;
					loop10:
					while (true) {
						int alt10=2;
						switch ( input.LA(1) ) {
						case KEY_DEC:
							{
							int LA10_2 = input.LA(2);
							if ( ((LA10_2 >= IDENTIFIER && LA10_2 <= KEY_WORDSIZE)||LA10_2==SEMI) ) {
								alt10=1;
							}

							}
							break;
						case KEY_HEX:
							{
							int LA10_3 = input.LA(2);
							if ( ((LA10_3 >= IDENTIFIER && LA10_3 <= KEY_WORDSIZE)||LA10_3==SEMI) ) {
								alt10=1;
							}

							}
							break;
						case KEY_NOFLOW:
							{
							int LA10_4 = input.LA(2);
							if ( ((LA10_4 >= IDENTIFIER && LA10_4 <= KEY_WORDSIZE)||LA10_4==SEMI) ) {
								alt10=1;
							}

							}
							break;
						case KEY_SIGNED:
							{
							int LA10_5 = input.LA(2);
							if ( ((LA10_5 >= IDENTIFIER && LA10_5 <= KEY_WORDSIZE)||LA10_5==SEMI) ) {
								alt10=1;
							}

							}
							break;
						}
						switch (alt10) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:108:9: contextfieldmod
							{
							pushFollow(FOLLOW_contextfieldmod_in_contextfieldmods588);
							contextfieldmod47=contextfieldmod();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) stream_contextfieldmod.add(contextfieldmod47.getTree());
							}
							break;

						default :
							if ( cnt10 >= 1 ) break loop10;
							if (state.backtracking>0) {state.failed=true; return retval;}
							EarlyExitException eee = new EarlyExitException(10, input);
							throw eee;
						}
						cnt10++;
					}

					// AST REWRITE
					// elements: contextfieldmod
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 108:26: -> ^( OP_FIELD_MODS[it, \"context field modifiers\"] ( contextfieldmod )+ )
					{
						// ghidra/sleigh/grammar/SleighParser.g:108:29: ^( OP_FIELD_MODS[it, \"context field modifiers\"] ( contextfieldmod )+ )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FIELD_MODS, it, "context field modifiers"), root_1);
						if ( !(stream_contextfieldmod.hasNext()) ) {
							throw new RewriteEarlyExitException();
						}
						while ( stream_contextfieldmod.hasNext() ) {
							adaptor.addChild(root_1, stream_contextfieldmod.nextTree());
						}
						stream_contextfieldmod.reset();

						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:109:9: 
					{
					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 109:9: -> OP_NO_FIELD_MOD[it, \"<no field mod>\"]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_NO_FIELD_MOD, it, "<no field mod>"));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "contextfieldmods"


	public static class contextfieldmod_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "contextfieldmod"
	// ghidra/sleigh/grammar/SleighParser.g:112:1: contextfieldmod : (lc= KEY_SIGNED -> OP_SIGNED[$lc] |lc= KEY_NOFLOW -> OP_NOFLOW[$lc] |lc= KEY_HEX -> OP_HEX[$lc] |lc= KEY_DEC -> OP_DEC[$lc] );
	public final SleighParser.contextfieldmod_return contextfieldmod() throws RecognitionException {
		SleighParser.contextfieldmod_return retval = new SleighParser.contextfieldmod_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_DEC=new RewriteRuleTokenStream(adaptor,"token KEY_DEC");
		RewriteRuleTokenStream stream_KEY_SIGNED=new RewriteRuleTokenStream(adaptor,"token KEY_SIGNED");
		RewriteRuleTokenStream stream_KEY_NOFLOW=new RewriteRuleTokenStream(adaptor,"token KEY_NOFLOW");
		RewriteRuleTokenStream stream_KEY_HEX=new RewriteRuleTokenStream(adaptor,"token KEY_HEX");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:113:5: (lc= KEY_SIGNED -> OP_SIGNED[$lc] |lc= KEY_NOFLOW -> OP_NOFLOW[$lc] |lc= KEY_HEX -> OP_HEX[$lc] |lc= KEY_DEC -> OP_DEC[$lc] )
			int alt12=4;
			switch ( input.LA(1) ) {
			case KEY_SIGNED:
				{
				alt12=1;
				}
				break;
			case KEY_NOFLOW:
				{
				alt12=2;
				}
				break;
			case KEY_HEX:
				{
				alt12=3;
				}
				break;
			case KEY_DEC:
				{
				alt12=4;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 12, 0, input);
				throw nvae;
			}
			switch (alt12) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:113:9: lc= KEY_SIGNED
					{
					lc=(Token)match(input,KEY_SIGNED,FOLLOW_KEY_SIGNED_in_contextfieldmod633); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_SIGNED.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 113:23: -> OP_SIGNED[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_SIGNED, lc));
					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:114:9: lc= KEY_NOFLOW
					{
					lc=(Token)match(input,KEY_NOFLOW,FOLLOW_KEY_NOFLOW_in_contextfieldmod650); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_NOFLOW.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 114:23: -> OP_NOFLOW[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_NOFLOW, lc));
					}


					retval.tree = root_0;
					}

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:115:9: lc= KEY_HEX
					{
					lc=(Token)match(input,KEY_HEX,FOLLOW_KEY_HEX_in_contextfieldmod667); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_HEX.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 115:20: -> OP_HEX[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_HEX, lc));
					}


					retval.tree = root_0;
					}

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighParser.g:116:9: lc= KEY_DEC
					{
					lc=(Token)match(input,KEY_DEC,FOLLOW_KEY_DEC_in_contextfieldmod684); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEC.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 116:20: -> OP_DEC[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_DEC, lc));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "contextfieldmod"


	public static class contextdef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "contextdef"
	// ghidra/sleigh/grammar/SleighParser.g:119:1: contextdef : lc= KEY_DEFINE rp= KEY_CONTEXT identifier contextfielddefs[$rp] -> ^( OP_CONTEXT[$lc, \"define context\"] identifier contextfielddefs ) ;
	public final SleighParser.contextdef_return contextdef() throws RecognitionException {
		SleighParser.contextdef_return retval = new SleighParser.contextdef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		ParserRuleReturnScope identifier48 =null;
		ParserRuleReturnScope contextfielddefs49 =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		RewriteRuleTokenStream stream_KEY_CONTEXT=new RewriteRuleTokenStream(adaptor,"token KEY_CONTEXT");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_contextfielddefs=new RewriteRuleSubtreeStream(adaptor,"rule contextfielddefs");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:120:2: (lc= KEY_DEFINE rp= KEY_CONTEXT identifier contextfielddefs[$rp] -> ^( OP_CONTEXT[$lc, \"define context\"] identifier contextfielddefs ) )
			// ghidra/sleigh/grammar/SleighParser.g:120:4: lc= KEY_DEFINE rp= KEY_CONTEXT identifier contextfielddefs[$rp]
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_contextdef705); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			rp=(Token)match(input,KEY_CONTEXT,FOLLOW_KEY_CONTEXT_in_contextdef709); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_CONTEXT.add(rp);

			pushFollow(FOLLOW_identifier_in_contextdef711);
			identifier48=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier48.getTree());
			pushFollow(FOLLOW_contextfielddefs_in_contextdef713);
			contextfielddefs49=contextfielddefs(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_contextfielddefs.add(contextfielddefs49.getTree());
			// AST REWRITE
			// elements: contextfielddefs, identifier
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 120:66: -> ^( OP_CONTEXT[$lc, \"define context\"] identifier contextfielddefs )
			{
				// ghidra/sleigh/grammar/SleighParser.g:120:69: ^( OP_CONTEXT[$lc, \"define context\"] identifier contextfielddefs )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_CONTEXT, lc, "define context"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				adaptor.addChild(root_1, stream_contextfielddefs.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "contextdef"


	public static class spacedef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "spacedef"
	// ghidra/sleigh/grammar/SleighParser.g:123:1: spacedef : lc= KEY_DEFINE KEY_SPACE identifier spacemods[$lc] -> ^( OP_SPACE[$lc, \"define space\"] identifier spacemods ) ;
	public final SleighParser.spacedef_return spacedef() throws RecognitionException {
		SleighParser.spacedef_return retval = new SleighParser.spacedef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token KEY_SPACE50=null;
		ParserRuleReturnScope identifier51 =null;
		ParserRuleReturnScope spacemods52 =null;

		CommonTree lc_tree=null;
		CommonTree KEY_SPACE50_tree=null;
		RewriteRuleTokenStream stream_KEY_SPACE=new RewriteRuleTokenStream(adaptor,"token KEY_SPACE");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_spacemods=new RewriteRuleSubtreeStream(adaptor,"rule spacemods");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:124:2: (lc= KEY_DEFINE KEY_SPACE identifier spacemods[$lc] -> ^( OP_SPACE[$lc, \"define space\"] identifier spacemods ) )
			// ghidra/sleigh/grammar/SleighParser.g:124:4: lc= KEY_DEFINE KEY_SPACE identifier spacemods[$lc]
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_spacedef738); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			KEY_SPACE50=(Token)match(input,KEY_SPACE,FOLLOW_KEY_SPACE_in_spacedef740); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_SPACE.add(KEY_SPACE50);

			pushFollow(FOLLOW_identifier_in_spacedef742);
			identifier51=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier51.getTree());
			pushFollow(FOLLOW_spacemods_in_spacedef744);
			spacemods52=spacemods(lc);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_spacemods.add(spacemods52.getTree());
			// AST REWRITE
			// elements: spacemods, identifier
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 124:54: -> ^( OP_SPACE[$lc, \"define space\"] identifier spacemods )
			{
				// ghidra/sleigh/grammar/SleighParser.g:124:57: ^( OP_SPACE[$lc, \"define space\"] identifier spacemods )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SPACE, lc, "define space"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				adaptor.addChild(root_1, stream_spacemods.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "spacedef"


	public static class spacemods_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "spacemods"
	// ghidra/sleigh/grammar/SleighParser.g:127:1: spacemods[Token lc] : ( spacemod )* -> ^( OP_SPACEMODS[$lc, \"space modifier\"] ( spacemod )* ) ;
	public final SleighParser.spacemods_return spacemods(Token lc) throws RecognitionException {
		SleighParser.spacemods_return retval = new SleighParser.spacemods_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope spacemod53 =null;

		RewriteRuleSubtreeStream stream_spacemod=new RewriteRuleSubtreeStream(adaptor,"rule spacemod");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:128:2: ( ( spacemod )* -> ^( OP_SPACEMODS[$lc, \"space modifier\"] ( spacemod )* ) )
			// ghidra/sleigh/grammar/SleighParser.g:128:4: ( spacemod )*
			{
			// ghidra/sleigh/grammar/SleighParser.g:128:4: ( spacemod )*
			loop13:
			while (true) {
				int alt13=2;
				int LA13_0 = input.LA(1);
				if ( (LA13_0==KEY_DEFAULT||LA13_0==KEY_SIZE||LA13_0==KEY_TYPE||LA13_0==KEY_WORDSIZE) ) {
					alt13=1;
				}

				switch (alt13) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:128:4: spacemod
					{
					pushFollow(FOLLOW_spacemod_in_spacemods768);
					spacemod53=spacemod();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_spacemod.add(spacemod53.getTree());
					}
					break;

				default :
					break loop13;
				}
			}

			// AST REWRITE
			// elements: spacemod
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 128:14: -> ^( OP_SPACEMODS[$lc, \"space modifier\"] ( spacemod )* )
			{
				// ghidra/sleigh/grammar/SleighParser.g:128:17: ^( OP_SPACEMODS[$lc, \"space modifier\"] ( spacemod )* )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SPACEMODS, lc, "space modifier"), root_1);
				// ghidra/sleigh/grammar/SleighParser.g:128:55: ( spacemod )*
				while ( stream_spacemod.hasNext() ) {
					adaptor.addChild(root_1, stream_spacemod.nextTree());
				}
				stream_spacemod.reset();

				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "spacemods"


	public static class spacemod_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "spacemod"
	// ghidra/sleigh/grammar/SleighParser.g:131:1: spacemod : ( typemod | sizemod | wordsizemod |lc= KEY_DEFAULT -> OP_DEFAULT[$lc] );
	public final SleighParser.spacemod_return spacemod() throws RecognitionException {
		SleighParser.spacemod_return retval = new SleighParser.spacemod_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope typemod54 =null;
		ParserRuleReturnScope sizemod55 =null;
		ParserRuleReturnScope wordsizemod56 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_DEFAULT=new RewriteRuleTokenStream(adaptor,"token KEY_DEFAULT");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:132:2: ( typemod | sizemod | wordsizemod |lc= KEY_DEFAULT -> OP_DEFAULT[$lc] )
			int alt14=4;
			switch ( input.LA(1) ) {
			case KEY_TYPE:
				{
				alt14=1;
				}
				break;
			case KEY_SIZE:
				{
				alt14=2;
				}
				break;
			case KEY_WORDSIZE:
				{
				alt14=3;
				}
				break;
			case KEY_DEFAULT:
				{
				alt14=4;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 14, 0, input);
				throw nvae;
			}
			switch (alt14) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:132:4: typemod
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_typemod_in_spacemod790);
					typemod54=typemod();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, typemod54.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:133:4: sizemod
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_sizemod_in_spacemod795);
					sizemod55=sizemod();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, sizemod55.getTree());

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:134:4: wordsizemod
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_wordsizemod_in_spacemod800);
					wordsizemod56=wordsizemod();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, wordsizemod56.getTree());

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighParser.g:135:4: lc= KEY_DEFAULT
					{
					lc=(Token)match(input,KEY_DEFAULT,FOLLOW_KEY_DEFAULT_in_spacemod807); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEFAULT.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 135:19: -> OP_DEFAULT[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_DEFAULT, lc));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "spacemod"


	public static class typemod_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "typemod"
	// ghidra/sleigh/grammar/SleighParser.g:138:1: typemod : lc= KEY_TYPE ASSIGN type -> ^( OP_TYPE[$lc] type ) ;
	public final SleighParser.typemod_return typemod() throws RecognitionException {
		SleighParser.typemod_return retval = new SleighParser.typemod_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token ASSIGN57=null;
		ParserRuleReturnScope type58 =null;

		CommonTree lc_tree=null;
		CommonTree ASSIGN57_tree=null;
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleTokenStream stream_KEY_TYPE=new RewriteRuleTokenStream(adaptor,"token KEY_TYPE");
		RewriteRuleSubtreeStream stream_type=new RewriteRuleSubtreeStream(adaptor,"rule type");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:139:2: (lc= KEY_TYPE ASSIGN type -> ^( OP_TYPE[$lc] type ) )
			// ghidra/sleigh/grammar/SleighParser.g:139:4: lc= KEY_TYPE ASSIGN type
			{
			lc=(Token)match(input,KEY_TYPE,FOLLOW_KEY_TYPE_in_typemod825); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_TYPE.add(lc);

			ASSIGN57=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_typemod827); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN57);

			pushFollow(FOLLOW_type_in_typemod829);
			type58=type();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_type.add(type58.getTree());
			// AST REWRITE
			// elements: type
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 139:28: -> ^( OP_TYPE[$lc] type )
			{
				// ghidra/sleigh/grammar/SleighParser.g:139:31: ^( OP_TYPE[$lc] type )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_TYPE, lc), root_1);
				adaptor.addChild(root_1, stream_type.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "typemod"


	public static class type_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "type"
	// ghidra/sleigh/grammar/SleighParser.g:142:1: type : identifier ;
	public final SleighParser.type_return type() throws RecognitionException {
		SleighParser.type_return retval = new SleighParser.type_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier59 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:143:2: ( identifier )
			// ghidra/sleigh/grammar/SleighParser.g:143:4: identifier
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_identifier_in_type849);
			identifier59=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier59.getTree());

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "type"


	public static class sizemod_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "sizemod"
	// ghidra/sleigh/grammar/SleighParser.g:146:1: sizemod : lc= KEY_SIZE ASSIGN integer -> ^( OP_SIZE[$lc] integer ) ;
	public final SleighParser.sizemod_return sizemod() throws RecognitionException {
		SleighParser.sizemod_return retval = new SleighParser.sizemod_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token ASSIGN60=null;
		ParserRuleReturnScope integer61 =null;

		CommonTree lc_tree=null;
		CommonTree ASSIGN60_tree=null;
		RewriteRuleTokenStream stream_KEY_SIZE=new RewriteRuleTokenStream(adaptor,"token KEY_SIZE");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:147:2: (lc= KEY_SIZE ASSIGN integer -> ^( OP_SIZE[$lc] integer ) )
			// ghidra/sleigh/grammar/SleighParser.g:147:4: lc= KEY_SIZE ASSIGN integer
			{
			lc=(Token)match(input,KEY_SIZE,FOLLOW_KEY_SIZE_in_sizemod862); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_SIZE.add(lc);

			ASSIGN60=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_sizemod864); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN60);

			pushFollow(FOLLOW_integer_in_sizemod866);
			integer61=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(integer61.getTree());
			// AST REWRITE
			// elements: integer
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 147:31: -> ^( OP_SIZE[$lc] integer )
			{
				// ghidra/sleigh/grammar/SleighParser.g:147:34: ^( OP_SIZE[$lc] integer )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SIZE, lc), root_1);
				adaptor.addChild(root_1, stream_integer.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "sizemod"


	public static class wordsizemod_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "wordsizemod"
	// ghidra/sleigh/grammar/SleighParser.g:150:1: wordsizemod : lc= KEY_WORDSIZE ASSIGN integer -> ^( OP_WORDSIZE[$lc] integer ) ;
	public final SleighParser.wordsizemod_return wordsizemod() throws RecognitionException {
		SleighParser.wordsizemod_return retval = new SleighParser.wordsizemod_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token ASSIGN62=null;
		ParserRuleReturnScope integer63 =null;

		CommonTree lc_tree=null;
		CommonTree ASSIGN62_tree=null;
		RewriteRuleTokenStream stream_KEY_WORDSIZE=new RewriteRuleTokenStream(adaptor,"token KEY_WORDSIZE");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:151:2: (lc= KEY_WORDSIZE ASSIGN integer -> ^( OP_WORDSIZE[$lc] integer ) )
			// ghidra/sleigh/grammar/SleighParser.g:151:4: lc= KEY_WORDSIZE ASSIGN integer
			{
			lc=(Token)match(input,KEY_WORDSIZE,FOLLOW_KEY_WORDSIZE_in_wordsizemod888); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_WORDSIZE.add(lc);

			ASSIGN62=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_wordsizemod890); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN62);

			pushFollow(FOLLOW_integer_in_wordsizemod892);
			integer63=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(integer63.getTree());
			// AST REWRITE
			// elements: integer
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 151:35: -> ^( OP_WORDSIZE[$lc] integer )
			{
				// ghidra/sleigh/grammar/SleighParser.g:151:38: ^( OP_WORDSIZE[$lc] integer )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_WORDSIZE, lc), root_1);
				adaptor.addChild(root_1, stream_integer.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "wordsizemod"


	public static class varnodedef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "varnodedef"
	// ghidra/sleigh/grammar/SleighParser.g:154:1: varnodedef : lc= KEY_DEFINE identifier KEY_OFFSET ASSIGN offset= integer KEY_SIZE rb= ASSIGN size= integer identifierlist[$rb] -> ^( OP_VARNODE[$lc, \"define varnode\"] identifier $offset $size identifierlist ) ;
	public final SleighParser.varnodedef_return varnodedef() throws RecognitionException {
		SleighParser.varnodedef_return retval = new SleighParser.varnodedef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rb=null;
		Token KEY_OFFSET65=null;
		Token ASSIGN66=null;
		Token KEY_SIZE67=null;
		ParserRuleReturnScope offset =null;
		ParserRuleReturnScope size =null;
		ParserRuleReturnScope identifier64 =null;
		ParserRuleReturnScope identifierlist68 =null;

		CommonTree lc_tree=null;
		CommonTree rb_tree=null;
		CommonTree KEY_OFFSET65_tree=null;
		CommonTree ASSIGN66_tree=null;
		CommonTree KEY_SIZE67_tree=null;
		RewriteRuleTokenStream stream_KEY_SIZE=new RewriteRuleTokenStream(adaptor,"token KEY_SIZE");
		RewriteRuleTokenStream stream_KEY_OFFSET=new RewriteRuleTokenStream(adaptor,"token KEY_OFFSET");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_identifierlist=new RewriteRuleSubtreeStream(adaptor,"rule identifierlist");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:155:2: (lc= KEY_DEFINE identifier KEY_OFFSET ASSIGN offset= integer KEY_SIZE rb= ASSIGN size= integer identifierlist[$rb] -> ^( OP_VARNODE[$lc, \"define varnode\"] identifier $offset $size identifierlist ) )
			// ghidra/sleigh/grammar/SleighParser.g:155:4: lc= KEY_DEFINE identifier KEY_OFFSET ASSIGN offset= integer KEY_SIZE rb= ASSIGN size= integer identifierlist[$rb]
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_varnodedef914); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			pushFollow(FOLLOW_identifier_in_varnodedef916);
			identifier64=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier64.getTree());
			KEY_OFFSET65=(Token)match(input,KEY_OFFSET,FOLLOW_KEY_OFFSET_in_varnodedef918); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_OFFSET.add(KEY_OFFSET65);

			ASSIGN66=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_varnodedef920); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN66);

			pushFollow(FOLLOW_integer_in_varnodedef924);
			offset=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(offset.getTree());
			KEY_SIZE67=(Token)match(input,KEY_SIZE,FOLLOW_KEY_SIZE_in_varnodedef926); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_SIZE.add(KEY_SIZE67);

			rb=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_varnodedef930); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(rb);

			pushFollow(FOLLOW_integer_in_varnodedef934);
			size=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(size.getTree());
			pushFollow(FOLLOW_identifierlist_in_varnodedef936);
			identifierlist68=identifierlist(rb);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifierlist.add(identifierlist68.getTree());
			// AST REWRITE
			// elements: size, identifierlist, offset, identifier
			// token labels: 
			// rule labels: size, offset, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_size=new RewriteRuleSubtreeStream(adaptor,"rule size",size!=null?size.getTree():null);
			RewriteRuleSubtreeStream stream_offset=new RewriteRuleSubtreeStream(adaptor,"rule offset",offset!=null?offset.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 156:3: -> ^( OP_VARNODE[$lc, \"define varnode\"] identifier $offset $size identifierlist )
			{
				// ghidra/sleigh/grammar/SleighParser.g:156:6: ^( OP_VARNODE[$lc, \"define varnode\"] identifier $offset $size identifierlist )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_VARNODE, lc, "define varnode"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				adaptor.addChild(root_1, stream_offset.nextTree());
				adaptor.addChild(root_1, stream_size.nextTree());
				adaptor.addChild(root_1, stream_identifierlist.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "varnodedef"


	public static class bitrangedef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "bitrangedef"
	// ghidra/sleigh/grammar/SleighParser.g:159:1: bitrangedef : lc= KEY_DEFINE KEY_BITRANGE bitranges -> ^( OP_BITRANGES[$lc, \"define bitrange\"] bitranges ) ;
	public final SleighParser.bitrangedef_return bitrangedef() throws RecognitionException {
		SleighParser.bitrangedef_return retval = new SleighParser.bitrangedef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token KEY_BITRANGE69=null;
		ParserRuleReturnScope bitranges70 =null;

		CommonTree lc_tree=null;
		CommonTree KEY_BITRANGE69_tree=null;
		RewriteRuleTokenStream stream_KEY_BITRANGE=new RewriteRuleTokenStream(adaptor,"token KEY_BITRANGE");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_bitranges=new RewriteRuleSubtreeStream(adaptor,"rule bitranges");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:160:2: (lc= KEY_DEFINE KEY_BITRANGE bitranges -> ^( OP_BITRANGES[$lc, \"define bitrange\"] bitranges ) )
			// ghidra/sleigh/grammar/SleighParser.g:160:4: lc= KEY_DEFINE KEY_BITRANGE bitranges
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_bitrangedef969); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			KEY_BITRANGE69=(Token)match(input,KEY_BITRANGE,FOLLOW_KEY_BITRANGE_in_bitrangedef971); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_BITRANGE.add(KEY_BITRANGE69);

			pushFollow(FOLLOW_bitranges_in_bitrangedef973);
			bitranges70=bitranges();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_bitranges.add(bitranges70.getTree());
			// AST REWRITE
			// elements: bitranges
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 160:41: -> ^( OP_BITRANGES[$lc, \"define bitrange\"] bitranges )
			{
				// ghidra/sleigh/grammar/SleighParser.g:160:44: ^( OP_BITRANGES[$lc, \"define bitrange\"] bitranges )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BITRANGES, lc, "define bitrange"), root_1);
				adaptor.addChild(root_1, stream_bitranges.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "bitrangedef"


	public static class bitranges_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "bitranges"
	// ghidra/sleigh/grammar/SleighParser.g:163:1: bitranges : ( bitrange )+ ;
	public final SleighParser.bitranges_return bitranges() throws RecognitionException {
		SleighParser.bitranges_return retval = new SleighParser.bitranges_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope bitrange71 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:164:2: ( ( bitrange )+ )
			// ghidra/sleigh/grammar/SleighParser.g:164:4: ( bitrange )+
			{
			root_0 = (CommonTree)adaptor.nil();


			// ghidra/sleigh/grammar/SleighParser.g:164:4: ( bitrange )+
			int cnt15=0;
			loop15:
			while (true) {
				int alt15=2;
				int LA15_0 = input.LA(1);
				if ( ((LA15_0 >= IDENTIFIER && LA15_0 <= KEY_WORDSIZE)) ) {
					alt15=1;
				}

				switch (alt15) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:164:4: bitrange
					{
					pushFollow(FOLLOW_bitrange_in_bitranges993);
					bitrange71=bitrange();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, bitrange71.getTree());

					}
					break;

				default :
					if ( cnt15 >= 1 ) break loop15;
					if (state.backtracking>0) {state.failed=true; return retval;}
					EarlyExitException eee = new EarlyExitException(15, input);
					throw eee;
				}
				cnt15++;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "bitranges"


	public static class bitrange_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "bitrange"
	// ghidra/sleigh/grammar/SleighParser.g:167:1: bitrange : a= identifier lc= ASSIGN b= identifier LBRACKET i= integer COMMA j= integer RBRACKET -> ^( OP_BITRANGE[$lc, \"bitrange definition\"] $a $b $i $j) ;
	public final SleighParser.bitrange_return bitrange() throws RecognitionException {
		SleighParser.bitrange_return retval = new SleighParser.bitrange_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token LBRACKET72=null;
		Token COMMA73=null;
		Token RBRACKET74=null;
		ParserRuleReturnScope a =null;
		ParserRuleReturnScope b =null;
		ParserRuleReturnScope i =null;
		ParserRuleReturnScope j =null;

		CommonTree lc_tree=null;
		CommonTree LBRACKET72_tree=null;
		CommonTree COMMA73_tree=null;
		CommonTree RBRACKET74_tree=null;
		RewriteRuleTokenStream stream_COMMA=new RewriteRuleTokenStream(adaptor,"token COMMA");
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:168:2: (a= identifier lc= ASSIGN b= identifier LBRACKET i= integer COMMA j= integer RBRACKET -> ^( OP_BITRANGE[$lc, \"bitrange definition\"] $a $b $i $j) )
			// ghidra/sleigh/grammar/SleighParser.g:168:4: a= identifier lc= ASSIGN b= identifier LBRACKET i= integer COMMA j= integer RBRACKET
			{
			pushFollow(FOLLOW_identifier_in_bitrange1007);
			a=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(a.getTree());
			lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_bitrange1011); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(lc);

			pushFollow(FOLLOW_identifier_in_bitrange1015);
			b=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(b.getTree());
			LBRACKET72=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_bitrange1017); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_LBRACKET.add(LBRACKET72);

			pushFollow(FOLLOW_integer_in_bitrange1021);
			i=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(i.getTree());
			COMMA73=(Token)match(input,COMMA,FOLLOW_COMMA_in_bitrange1023); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_COMMA.add(COMMA73);

			pushFollow(FOLLOW_integer_in_bitrange1027);
			j=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(j.getTree());
			RBRACKET74=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_bitrange1029); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RBRACKET.add(RBRACKET74);

			// AST REWRITE
			// elements: i, a, b, j
			// token labels: 
			// rule labels: a, b, i, j, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_a=new RewriteRuleSubtreeStream(adaptor,"rule a",a!=null?a.getTree():null);
			RewriteRuleSubtreeStream stream_b=new RewriteRuleSubtreeStream(adaptor,"rule b",b!=null?b.getTree():null);
			RewriteRuleSubtreeStream stream_i=new RewriteRuleSubtreeStream(adaptor,"rule i",i!=null?i.getTree():null);
			RewriteRuleSubtreeStream stream_j=new RewriteRuleSubtreeStream(adaptor,"rule j",j!=null?j.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 168:84: -> ^( OP_BITRANGE[$lc, \"bitrange definition\"] $a $b $i $j)
			{
				// ghidra/sleigh/grammar/SleighParser.g:168:87: ^( OP_BITRANGE[$lc, \"bitrange definition\"] $a $b $i $j)
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BITRANGE, lc, "bitrange definition"), root_1);
				adaptor.addChild(root_1, stream_a.nextTree());
				adaptor.addChild(root_1, stream_b.nextTree());
				adaptor.addChild(root_1, stream_i.nextTree());
				adaptor.addChild(root_1, stream_j.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "bitrange"


	public static class pcodeopdef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pcodeopdef"
	// ghidra/sleigh/grammar/SleighParser.g:171:1: pcodeopdef : lc= KEY_DEFINE rb= KEY_PCODEOP identifierlist[$rb] -> ^( OP_PCODEOP[$lc, \"define pcodeop\"] identifierlist ) ;
	public final SleighParser.pcodeopdef_return pcodeopdef() throws RecognitionException {
		SleighParser.pcodeopdef_return retval = new SleighParser.pcodeopdef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rb=null;
		ParserRuleReturnScope identifierlist75 =null;

		CommonTree lc_tree=null;
		CommonTree rb_tree=null;
		RewriteRuleTokenStream stream_KEY_PCODEOP=new RewriteRuleTokenStream(adaptor,"token KEY_PCODEOP");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_identifierlist=new RewriteRuleSubtreeStream(adaptor,"rule identifierlist");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:172:2: (lc= KEY_DEFINE rb= KEY_PCODEOP identifierlist[$rb] -> ^( OP_PCODEOP[$lc, \"define pcodeop\"] identifierlist ) )
			// ghidra/sleigh/grammar/SleighParser.g:172:4: lc= KEY_DEFINE rb= KEY_PCODEOP identifierlist[$rb]
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_pcodeopdef1061); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			rb=(Token)match(input,KEY_PCODEOP,FOLLOW_KEY_PCODEOP_in_pcodeopdef1065); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_PCODEOP.add(rb);

			pushFollow(FOLLOW_identifierlist_in_pcodeopdef1067);
			identifierlist75=identifierlist(rb);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifierlist.add(identifierlist75.getTree());
			// AST REWRITE
			// elements: identifierlist
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 172:53: -> ^( OP_PCODEOP[$lc, \"define pcodeop\"] identifierlist )
			{
				// ghidra/sleigh/grammar/SleighParser.g:172:56: ^( OP_PCODEOP[$lc, \"define pcodeop\"] identifierlist )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PCODEOP, lc, "define pcodeop"), root_1);
				adaptor.addChild(root_1, stream_identifierlist.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pcodeopdef"


	public static class valueattach_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "valueattach"
	// ghidra/sleigh/grammar/SleighParser.g:175:1: valueattach : lc= KEY_ATTACH rp= KEY_VALUES identifierlist[$rp] intblist[$rp] -> ^( OP_VALUES[$lc, \"attach values\"] identifierlist intblist ) ;
	public final SleighParser.valueattach_return valueattach() throws RecognitionException {
		SleighParser.valueattach_return retval = new SleighParser.valueattach_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		ParserRuleReturnScope identifierlist76 =null;
		ParserRuleReturnScope intblist77 =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		RewriteRuleTokenStream stream_KEY_ATTACH=new RewriteRuleTokenStream(adaptor,"token KEY_ATTACH");
		RewriteRuleTokenStream stream_KEY_VALUES=new RewriteRuleTokenStream(adaptor,"token KEY_VALUES");
		RewriteRuleSubtreeStream stream_intblist=new RewriteRuleSubtreeStream(adaptor,"rule intblist");
		RewriteRuleSubtreeStream stream_identifierlist=new RewriteRuleSubtreeStream(adaptor,"rule identifierlist");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:176:2: (lc= KEY_ATTACH rp= KEY_VALUES identifierlist[$rp] intblist[$rp] -> ^( OP_VALUES[$lc, \"attach values\"] identifierlist intblist ) )
			// ghidra/sleigh/grammar/SleighParser.g:176:4: lc= KEY_ATTACH rp= KEY_VALUES identifierlist[$rp] intblist[$rp]
			{
			lc=(Token)match(input,KEY_ATTACH,FOLLOW_KEY_ATTACH_in_valueattach1090); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_ATTACH.add(lc);

			rp=(Token)match(input,KEY_VALUES,FOLLOW_KEY_VALUES_in_valueattach1094); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_VALUES.add(rp);

			pushFollow(FOLLOW_identifierlist_in_valueattach1096);
			identifierlist76=identifierlist(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifierlist.add(identifierlist76.getTree());
			pushFollow(FOLLOW_intblist_in_valueattach1099);
			intblist77=intblist(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_intblist.add(intblist77.getTree());
			// AST REWRITE
			// elements: identifierlist, intblist
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 176:66: -> ^( OP_VALUES[$lc, \"attach values\"] identifierlist intblist )
			{
				// ghidra/sleigh/grammar/SleighParser.g:176:69: ^( OP_VALUES[$lc, \"attach values\"] identifierlist intblist )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_VALUES, lc, "attach values"), root_1);
				adaptor.addChild(root_1, stream_identifierlist.nextTree());
				adaptor.addChild(root_1, stream_intblist.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "valueattach"


	public static class nameattach_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "nameattach"
	// ghidra/sleigh/grammar/SleighParser.g:179:1: nameattach : lc= KEY_ATTACH rp= KEY_NAMES a= identifierlist[$rp] b= stringoridentlist[$rp] -> ^( OP_NAMES[$lc, \"attach names\"] $a $b) ;
	public final SleighParser.nameattach_return nameattach() throws RecognitionException {
		SleighParser.nameattach_return retval = new SleighParser.nameattach_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		ParserRuleReturnScope a =null;
		ParserRuleReturnScope b =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		RewriteRuleTokenStream stream_KEY_ATTACH=new RewriteRuleTokenStream(adaptor,"token KEY_ATTACH");
		RewriteRuleTokenStream stream_KEY_NAMES=new RewriteRuleTokenStream(adaptor,"token KEY_NAMES");
		RewriteRuleSubtreeStream stream_identifierlist=new RewriteRuleSubtreeStream(adaptor,"rule identifierlist");
		RewriteRuleSubtreeStream stream_stringoridentlist=new RewriteRuleSubtreeStream(adaptor,"rule stringoridentlist");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:180:2: (lc= KEY_ATTACH rp= KEY_NAMES a= identifierlist[$rp] b= stringoridentlist[$rp] -> ^( OP_NAMES[$lc, \"attach names\"] $a $b) )
			// ghidra/sleigh/grammar/SleighParser.g:180:4: lc= KEY_ATTACH rp= KEY_NAMES a= identifierlist[$rp] b= stringoridentlist[$rp]
			{
			lc=(Token)match(input,KEY_ATTACH,FOLLOW_KEY_ATTACH_in_nameattach1124); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_ATTACH.add(lc);

			rp=(Token)match(input,KEY_NAMES,FOLLOW_KEY_NAMES_in_nameattach1128); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_NAMES.add(rp);

			pushFollow(FOLLOW_identifierlist_in_nameattach1132);
			a=identifierlist(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifierlist.add(a.getTree());
			pushFollow(FOLLOW_stringoridentlist_in_nameattach1137);
			b=stringoridentlist(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_stringoridentlist.add(b.getTree());
			// AST REWRITE
			// elements: a, b
			// token labels: 
			// rule labels: a, b, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_a=new RewriteRuleSubtreeStream(adaptor,"rule a",a!=null?a.getTree():null);
			RewriteRuleSubtreeStream stream_b=new RewriteRuleSubtreeStream(adaptor,"rule b",b!=null?b.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 180:78: -> ^( OP_NAMES[$lc, \"attach names\"] $a $b)
			{
				// ghidra/sleigh/grammar/SleighParser.g:180:81: ^( OP_NAMES[$lc, \"attach names\"] $a $b)
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NAMES, lc, "attach names"), root_1);
				adaptor.addChild(root_1, stream_a.nextTree());
				adaptor.addChild(root_1, stream_b.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "nameattach"


	public static class varattach_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "varattach"
	// ghidra/sleigh/grammar/SleighParser.g:183:1: varattach : lc= KEY_ATTACH rp= KEY_VARIABLES a= identifierlist[$rp] b= identifierlist[$rp] -> ^( OP_VARIABLES[$lc, \"attach variables\"] $a $b) ;
	public final SleighParser.varattach_return varattach() throws RecognitionException {
		SleighParser.varattach_return retval = new SleighParser.varattach_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		ParserRuleReturnScope a =null;
		ParserRuleReturnScope b =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		RewriteRuleTokenStream stream_KEY_VARIABLES=new RewriteRuleTokenStream(adaptor,"token KEY_VARIABLES");
		RewriteRuleTokenStream stream_KEY_ATTACH=new RewriteRuleTokenStream(adaptor,"token KEY_ATTACH");
		RewriteRuleSubtreeStream stream_identifierlist=new RewriteRuleSubtreeStream(adaptor,"rule identifierlist");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:184:2: (lc= KEY_ATTACH rp= KEY_VARIABLES a= identifierlist[$rp] b= identifierlist[$rp] -> ^( OP_VARIABLES[$lc, \"attach variables\"] $a $b) )
			// ghidra/sleigh/grammar/SleighParser.g:184:4: lc= KEY_ATTACH rp= KEY_VARIABLES a= identifierlist[$rp] b= identifierlist[$rp]
			{
			lc=(Token)match(input,KEY_ATTACH,FOLLOW_KEY_ATTACH_in_varattach1164); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_ATTACH.add(lc);

			rp=(Token)match(input,KEY_VARIABLES,FOLLOW_KEY_VARIABLES_in_varattach1168); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_VARIABLES.add(rp);

			pushFollow(FOLLOW_identifierlist_in_varattach1172);
			a=identifierlist(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifierlist.add(a.getTree());
			pushFollow(FOLLOW_identifierlist_in_varattach1177);
			b=identifierlist(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifierlist.add(b.getTree());
			// AST REWRITE
			// elements: a, b
			// token labels: 
			// rule labels: a, b, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_a=new RewriteRuleSubtreeStream(adaptor,"rule a",a!=null?a.getTree():null);
			RewriteRuleSubtreeStream stream_b=new RewriteRuleSubtreeStream(adaptor,"rule b",b!=null?b.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 184:79: -> ^( OP_VARIABLES[$lc, \"attach variables\"] $a $b)
			{
				// ghidra/sleigh/grammar/SleighParser.g:184:82: ^( OP_VARIABLES[$lc, \"attach variables\"] $a $b)
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_VARIABLES, lc, "attach variables"), root_1);
				adaptor.addChild(root_1, stream_a.nextTree());
				adaptor.addChild(root_1, stream_b.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "varattach"


	public static class identifierlist_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "identifierlist"
	// ghidra/sleigh/grammar/SleighParser.g:187:1: identifierlist[Token lc] : ( LBRACKET ( id_or_wild )+ RBRACKET -> ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] ( id_or_wild )+ ) | id_or_wild -> ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] id_or_wild ) );
	public final SleighParser.identifierlist_return identifierlist(Token lc) throws RecognitionException {
		SleighParser.identifierlist_return retval = new SleighParser.identifierlist_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LBRACKET78=null;
		Token RBRACKET80=null;
		ParserRuleReturnScope id_or_wild79 =null;
		ParserRuleReturnScope id_or_wild81 =null;

		CommonTree LBRACKET78_tree=null;
		CommonTree RBRACKET80_tree=null;
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleSubtreeStream stream_id_or_wild=new RewriteRuleSubtreeStream(adaptor,"rule id_or_wild");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:188:2: ( LBRACKET ( id_or_wild )+ RBRACKET -> ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] ( id_or_wild )+ ) | id_or_wild -> ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] id_or_wild ) )
			int alt17=2;
			int LA17_0 = input.LA(1);
			if ( (LA17_0==LBRACKET) ) {
				alt17=1;
			}
			else if ( ((LA17_0 >= IDENTIFIER && LA17_0 <= KEY_WORDSIZE)||LA17_0==UNDERSCORE) ) {
				alt17=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 17, 0, input);
				throw nvae;
			}

			switch (alt17) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:188:4: LBRACKET ( id_or_wild )+ RBRACKET
					{
					LBRACKET78=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_identifierlist1203); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LBRACKET.add(LBRACKET78);

					// ghidra/sleigh/grammar/SleighParser.g:188:13: ( id_or_wild )+
					int cnt16=0;
					loop16:
					while (true) {
						int alt16=2;
						int LA16_0 = input.LA(1);
						if ( ((LA16_0 >= IDENTIFIER && LA16_0 <= KEY_WORDSIZE)||LA16_0==UNDERSCORE) ) {
							alt16=1;
						}

						switch (alt16) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:188:13: id_or_wild
							{
							pushFollow(FOLLOW_id_or_wild_in_identifierlist1205);
							id_or_wild79=id_or_wild();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) stream_id_or_wild.add(id_or_wild79.getTree());
							}
							break;

						default :
							if ( cnt16 >= 1 ) break loop16;
							if (state.backtracking>0) {state.failed=true; return retval;}
							EarlyExitException eee = new EarlyExitException(16, input);
							throw eee;
						}
						cnt16++;
					}

					RBRACKET80=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_identifierlist1208); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RBRACKET.add(RBRACKET80);

					// AST REWRITE
					// elements: id_or_wild
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 188:34: -> ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] ( id_or_wild )+ )
					{
						// ghidra/sleigh/grammar/SleighParser.g:188:37: ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] ( id_or_wild )+ )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER_LIST, lc, "identifier list"), root_1);
						if ( !(stream_id_or_wild.hasNext()) ) {
							throw new RewriteEarlyExitException();
						}
						while ( stream_id_or_wild.hasNext() ) {
							adaptor.addChild(root_1, stream_id_or_wild.nextTree());
						}
						stream_id_or_wild.reset();

						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:189:4: id_or_wild
					{
					pushFollow(FOLLOW_id_or_wild_in_identifierlist1223);
					id_or_wild81=id_or_wild();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_id_or_wild.add(id_or_wild81.getTree());
					// AST REWRITE
					// elements: id_or_wild
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 189:15: -> ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] id_or_wild )
					{
						// ghidra/sleigh/grammar/SleighParser.g:189:18: ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] id_or_wild )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER_LIST, lc, "identifier list"), root_1);
						adaptor.addChild(root_1, stream_id_or_wild.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "identifierlist"


	public static class stringoridentlist_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "stringoridentlist"
	// ghidra/sleigh/grammar/SleighParser.g:192:1: stringoridentlist[Token lc] : ( LBRACKET ( stringorident )+ RBRACKET -> ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] ( stringorident )+ ) | stringorident -> ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] stringorident ) );
	public final SleighParser.stringoridentlist_return stringoridentlist(Token lc) throws RecognitionException {
		SleighParser.stringoridentlist_return retval = new SleighParser.stringoridentlist_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LBRACKET82=null;
		Token RBRACKET84=null;
		ParserRuleReturnScope stringorident83 =null;
		ParserRuleReturnScope stringorident85 =null;

		CommonTree LBRACKET82_tree=null;
		CommonTree RBRACKET84_tree=null;
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleSubtreeStream stream_stringorident=new RewriteRuleSubtreeStream(adaptor,"rule stringorident");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:193:2: ( LBRACKET ( stringorident )+ RBRACKET -> ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] ( stringorident )+ ) | stringorident -> ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] stringorident ) )
			int alt19=2;
			int LA19_0 = input.LA(1);
			if ( (LA19_0==LBRACKET) ) {
				alt19=1;
			}
			else if ( ((LA19_0 >= IDENTIFIER && LA19_0 <= KEY_WORDSIZE)||LA19_0==QSTRING||LA19_0==UNDERSCORE) ) {
				alt19=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 19, 0, input);
				throw nvae;
			}

			switch (alt19) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:193:4: LBRACKET ( stringorident )+ RBRACKET
					{
					LBRACKET82=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_stringoridentlist1244); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LBRACKET.add(LBRACKET82);

					// ghidra/sleigh/grammar/SleighParser.g:193:13: ( stringorident )+
					int cnt18=0;
					loop18:
					while (true) {
						int alt18=2;
						int LA18_0 = input.LA(1);
						if ( ((LA18_0 >= IDENTIFIER && LA18_0 <= KEY_WORDSIZE)||LA18_0==QSTRING||LA18_0==UNDERSCORE) ) {
							alt18=1;
						}

						switch (alt18) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:193:13: stringorident
							{
							pushFollow(FOLLOW_stringorident_in_stringoridentlist1246);
							stringorident83=stringorident();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) stream_stringorident.add(stringorident83.getTree());
							}
							break;

						default :
							if ( cnt18 >= 1 ) break loop18;
							if (state.backtracking>0) {state.failed=true; return retval;}
							EarlyExitException eee = new EarlyExitException(18, input);
							throw eee;
						}
						cnt18++;
					}

					RBRACKET84=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_stringoridentlist1249); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RBRACKET.add(RBRACKET84);

					// AST REWRITE
					// elements: stringorident
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 193:37: -> ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] ( stringorident )+ )
					{
						// ghidra/sleigh/grammar/SleighParser.g:193:40: ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] ( stringorident )+ )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING_OR_IDENT_LIST, lc, "string or identifier list"), root_1);
						if ( !(stream_stringorident.hasNext()) ) {
							throw new RewriteEarlyExitException();
						}
						while ( stream_stringorident.hasNext() ) {
							adaptor.addChild(root_1, stream_stringorident.nextTree());
						}
						stream_stringorident.reset();

						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:194:4: stringorident
					{
					pushFollow(FOLLOW_stringorident_in_stringoridentlist1264);
					stringorident85=stringorident();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_stringorident.add(stringorident85.getTree());
					// AST REWRITE
					// elements: stringorident
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 194:18: -> ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] stringorident )
					{
						// ghidra/sleigh/grammar/SleighParser.g:194:21: ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] stringorident )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING_OR_IDENT_LIST, lc, "string or identifier list"), root_1);
						adaptor.addChild(root_1, stream_stringorident.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "stringoridentlist"


	public static class stringorident_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "stringorident"
	// ghidra/sleigh/grammar/SleighParser.g:197:1: stringorident : ( id_or_wild | qstring );
	public final SleighParser.stringorident_return stringorident() throws RecognitionException {
		SleighParser.stringorident_return retval = new SleighParser.stringorident_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope id_or_wild86 =null;
		ParserRuleReturnScope qstring87 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:198:2: ( id_or_wild | qstring )
			int alt20=2;
			int LA20_0 = input.LA(1);
			if ( ((LA20_0 >= IDENTIFIER && LA20_0 <= KEY_WORDSIZE)||LA20_0==UNDERSCORE) ) {
				alt20=1;
			}
			else if ( (LA20_0==QSTRING) ) {
				alt20=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 20, 0, input);
				throw nvae;
			}

			switch (alt20) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:198:4: id_or_wild
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_id_or_wild_in_stringorident1284);
					id_or_wild86=id_or_wild();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, id_or_wild86.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:199:4: qstring
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_qstring_in_stringorident1289);
					qstring87=qstring();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, qstring87.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "stringorident"


	public static class intblist_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "intblist"
	// ghidra/sleigh/grammar/SleighParser.g:202:1: intblist[Token lc] : ( LBRACKET ( intbpart )+ RBRACKET -> ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] ( intbpart )+ ) | neginteger -> ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] neginteger ) );
	public final SleighParser.intblist_return intblist(Token lc) throws RecognitionException {
		SleighParser.intblist_return retval = new SleighParser.intblist_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LBRACKET88=null;
		Token RBRACKET90=null;
		ParserRuleReturnScope intbpart89 =null;
		ParserRuleReturnScope neginteger91 =null;

		CommonTree LBRACKET88_tree=null;
		CommonTree RBRACKET90_tree=null;
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleSubtreeStream stream_intbpart=new RewriteRuleSubtreeStream(adaptor,"rule intbpart");
		RewriteRuleSubtreeStream stream_neginteger=new RewriteRuleSubtreeStream(adaptor,"rule neginteger");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:203:2: ( LBRACKET ( intbpart )+ RBRACKET -> ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] ( intbpart )+ ) | neginteger -> ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] neginteger ) )
			int alt22=2;
			int LA22_0 = input.LA(1);
			if ( (LA22_0==LBRACKET) ) {
				alt22=1;
			}
			else if ( (LA22_0==BIN_INT||LA22_0==DEC_INT||LA22_0==HEX_INT||LA22_0==MINUS) ) {
				alt22=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 22, 0, input);
				throw nvae;
			}

			switch (alt22) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:203:4: LBRACKET ( intbpart )+ RBRACKET
					{
					LBRACKET88=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_intblist1301); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LBRACKET.add(LBRACKET88);

					// ghidra/sleigh/grammar/SleighParser.g:203:13: ( intbpart )+
					int cnt21=0;
					loop21:
					while (true) {
						int alt21=2;
						int LA21_0 = input.LA(1);
						if ( (LA21_0==BIN_INT||LA21_0==DEC_INT||LA21_0==HEX_INT||LA21_0==MINUS||LA21_0==UNDERSCORE) ) {
							alt21=1;
						}

						switch (alt21) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:203:13: intbpart
							{
							pushFollow(FOLLOW_intbpart_in_intblist1303);
							intbpart89=intbpart();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) stream_intbpart.add(intbpart89.getTree());
							}
							break;

						default :
							if ( cnt21 >= 1 ) break loop21;
							if (state.backtracking>0) {state.failed=true; return retval;}
							EarlyExitException eee = new EarlyExitException(21, input);
							throw eee;
						}
						cnt21++;
					}

					RBRACKET90=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_intblist1306); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RBRACKET.add(RBRACKET90);

					// AST REWRITE
					// elements: intbpart
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 203:32: -> ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] ( intbpart )+ )
					{
						// ghidra/sleigh/grammar/SleighParser.g:203:35: ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] ( intbpart )+ )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_INTBLIST, lc, "integer or wildcard list"), root_1);
						if ( !(stream_intbpart.hasNext()) ) {
							throw new RewriteEarlyExitException();
						}
						while ( stream_intbpart.hasNext() ) {
							adaptor.addChild(root_1, stream_intbpart.nextTree());
						}
						stream_intbpart.reset();

						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:204:4: neginteger
					{
					pushFollow(FOLLOW_neginteger_in_intblist1321);
					neginteger91=neginteger();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_neginteger.add(neginteger91.getTree());
					// AST REWRITE
					// elements: neginteger
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 204:15: -> ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] neginteger )
					{
						// ghidra/sleigh/grammar/SleighParser.g:204:18: ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] neginteger )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_INTBLIST, lc, "integer or wildcard list"), root_1);
						adaptor.addChild(root_1, stream_neginteger.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "intblist"


	public static class intbpart_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "intbpart"
	// ghidra/sleigh/grammar/SleighParser.g:207:1: intbpart : ( neginteger |lc= UNDERSCORE -> OP_WILDCARD[$lc] );
	public final SleighParser.intbpart_return intbpart() throws RecognitionException {
		SleighParser.intbpart_return retval = new SleighParser.intbpart_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope neginteger92 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_UNDERSCORE=new RewriteRuleTokenStream(adaptor,"token UNDERSCORE");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:208:2: ( neginteger |lc= UNDERSCORE -> OP_WILDCARD[$lc] )
			int alt23=2;
			int LA23_0 = input.LA(1);
			if ( (LA23_0==BIN_INT||LA23_0==DEC_INT||LA23_0==HEX_INT||LA23_0==MINUS) ) {
				alt23=1;
			}
			else if ( (LA23_0==UNDERSCORE) ) {
				alt23=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 23, 0, input);
				throw nvae;
			}

			switch (alt23) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:208:4: neginteger
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_neginteger_in_intbpart1341);
					neginteger92=neginteger();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, neginteger92.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:209:4: lc= UNDERSCORE
					{
					lc=(Token)match(input,UNDERSCORE,FOLLOW_UNDERSCORE_in_intbpart1348); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_UNDERSCORE.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 209:18: -> OP_WILDCARD[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_WILDCARD, lc));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "intbpart"


	public static class neginteger_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "neginteger"
	// ghidra/sleigh/grammar/SleighParser.g:212:1: neginteger : ( integer |lc= MINUS integer -> ^( OP_NEGATE[$lc] integer ) );
	public final SleighParser.neginteger_return neginteger() throws RecognitionException {
		SleighParser.neginteger_return retval = new SleighParser.neginteger_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope integer93 =null;
		ParserRuleReturnScope integer94 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:213:2: ( integer |lc= MINUS integer -> ^( OP_NEGATE[$lc] integer ) )
			int alt24=2;
			int LA24_0 = input.LA(1);
			if ( (LA24_0==BIN_INT||LA24_0==DEC_INT||LA24_0==HEX_INT) ) {
				alt24=1;
			}
			else if ( (LA24_0==MINUS) ) {
				alt24=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 24, 0, input);
				throw nvae;
			}

			switch (alt24) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:213:4: integer
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_integer_in_neginteger1364);
					integer93=integer();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, integer93.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:214:4: lc= MINUS integer
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_neginteger1371); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_MINUS.add(lc);

					pushFollow(FOLLOW_integer_in_neginteger1373);
					integer94=integer();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_integer.add(integer94.getTree());
					// AST REWRITE
					// elements: integer
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 214:21: -> ^( OP_NEGATE[$lc] integer )
					{
						// ghidra/sleigh/grammar/SleighParser.g:214:24: ^( OP_NEGATE[$lc] integer )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NEGATE, lc), root_1);
						adaptor.addChild(root_1, stream_integer.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "neginteger"


	public static class constructorlike_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "constructorlike"
	// ghidra/sleigh/grammar/SleighParser.g:217:1: constructorlike : ( macrodef | withblock | constructor );
	public final SleighParser.constructorlike_return constructorlike() throws RecognitionException {
		SleighParser.constructorlike_return retval = new SleighParser.constructorlike_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope macrodef95 =null;
		ParserRuleReturnScope withblock96 =null;
		ParserRuleReturnScope constructor97 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:218:2: ( macrodef | withblock | constructor )
			int alt25=3;
			switch ( input.LA(1) ) {
			case KEY_MACRO:
				{
				int LA25_1 = input.LA(2);
				if ( ((LA25_1 >= IDENTIFIER && LA25_1 <= KEY_WORDSIZE)) ) {
					alt25=1;
				}
				else if ( (LA25_1==COLON) ) {
					alt25=3;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 25, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case RES_WITH:
				{
				alt25=2;
				}
				break;
			case COLON:
			case IDENTIFIER:
			case KEY_ALIGNMENT:
			case KEY_ATTACH:
			case KEY_BIG:
			case KEY_BITRANGE:
			case KEY_BUILD:
			case KEY_CALL:
			case KEY_CONTEXT:
			case KEY_CROSSBUILD:
			case KEY_DEC:
			case KEY_DEFAULT:
			case KEY_DEFINE:
			case KEY_ENDIAN:
			case KEY_EXPORT:
			case KEY_GOTO:
			case KEY_HEX:
			case KEY_LITTLE:
			case KEY_LOCAL:
			case KEY_NAMES:
			case KEY_NOFLOW:
			case KEY_OFFSET:
			case KEY_PCODEOP:
			case KEY_RETURN:
			case KEY_SIGNED:
			case KEY_SIZE:
			case KEY_SPACE:
			case KEY_TOKEN:
			case KEY_TYPE:
			case KEY_UNIMPL:
			case KEY_VALUES:
			case KEY_VARIABLES:
			case KEY_WORDSIZE:
				{
				alt25=3;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 25, 0, input);
				throw nvae;
			}
			switch (alt25) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:218:4: macrodef
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_macrodef_in_constructorlike1393);
					macrodef95=macrodef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, macrodef95.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:219:4: withblock
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_withblock_in_constructorlike1398);
					withblock96=withblock();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, withblock96.getTree());

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:220:4: constructor
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_constructor_in_constructorlike1403);
					constructor97=constructor();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, constructor97.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "constructorlike"


	public static class macrodef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "macrodef"
	// ghidra/sleigh/grammar/SleighParser.g:223:1: macrodef : lc= KEY_MACRO identifier lp= LPAREN arguments[$lp] RPAREN semanticbody -> ^( OP_MACRO[$lc, \"macro\"] identifier arguments semanticbody ) ;
	public final SleighParser.macrodef_return macrodef() throws RecognitionException {
		SleighParser.macrodef_return retval = new SleighParser.macrodef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token lp=null;
		Token RPAREN100=null;
		ParserRuleReturnScope identifier98 =null;
		ParserRuleReturnScope arguments99 =null;
		ParserRuleReturnScope semanticbody101 =null;

		CommonTree lc_tree=null;
		CommonTree lp_tree=null;
		CommonTree RPAREN100_tree=null;
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleTokenStream stream_KEY_MACRO=new RewriteRuleTokenStream(adaptor,"token KEY_MACRO");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_semanticbody=new RewriteRuleSubtreeStream(adaptor,"rule semanticbody");
		RewriteRuleSubtreeStream stream_arguments=new RewriteRuleSubtreeStream(adaptor,"rule arguments");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:224:2: (lc= KEY_MACRO identifier lp= LPAREN arguments[$lp] RPAREN semanticbody -> ^( OP_MACRO[$lc, \"macro\"] identifier arguments semanticbody ) )
			// ghidra/sleigh/grammar/SleighParser.g:224:4: lc= KEY_MACRO identifier lp= LPAREN arguments[$lp] RPAREN semanticbody
			{
			lc=(Token)match(input,KEY_MACRO,FOLLOW_KEY_MACRO_in_macrodef1416); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_MACRO.add(lc);

			pushFollow(FOLLOW_identifier_in_macrodef1418);
			identifier98=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier98.getTree());
			lp=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_macrodef1422); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_LPAREN.add(lp);

			pushFollow(FOLLOW_arguments_in_macrodef1424);
			arguments99=arguments(lp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_arguments.add(arguments99.getTree());
			RPAREN100=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_macrodef1427); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RPAREN.add(RPAREN100);

			pushFollow(FOLLOW_semanticbody_in_macrodef1429);
			semanticbody101=semanticbody();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_semanticbody.add(semanticbody101.getTree());
			// AST REWRITE
			// elements: semanticbody, identifier, arguments
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 224:73: -> ^( OP_MACRO[$lc, \"macro\"] identifier arguments semanticbody )
			{
				// ghidra/sleigh/grammar/SleighParser.g:224:76: ^( OP_MACRO[$lc, \"macro\"] identifier arguments semanticbody )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_MACRO, lc, "macro"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				adaptor.addChild(root_1, stream_arguments.nextTree());
				adaptor.addChild(root_1, stream_semanticbody.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "macrodef"


	public static class arguments_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "arguments"
	// ghidra/sleigh/grammar/SleighParser.g:227:1: arguments[Token lc] : ( oplist -> ^( OP_ARGUMENTS[$lc, \"arguments\"] oplist ) | -> ^( OP_EMPTY_LIST[$lc, \"no arguments\"] ) );
	public final SleighParser.arguments_return arguments(Token lc) throws RecognitionException {
		SleighParser.arguments_return retval = new SleighParser.arguments_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope oplist102 =null;

		RewriteRuleSubtreeStream stream_oplist=new RewriteRuleSubtreeStream(adaptor,"rule oplist");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:228:2: ( oplist -> ^( OP_ARGUMENTS[$lc, \"arguments\"] oplist ) | -> ^( OP_EMPTY_LIST[$lc, \"no arguments\"] ) )
			int alt26=2;
			int LA26_0 = input.LA(1);
			if ( ((LA26_0 >= IDENTIFIER && LA26_0 <= KEY_WORDSIZE)) ) {
				alt26=1;
			}
			else if ( (LA26_0==RPAREN) ) {
				alt26=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 26, 0, input);
				throw nvae;
			}

			switch (alt26) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:228:4: oplist
					{
					pushFollow(FOLLOW_oplist_in_arguments1454);
					oplist102=oplist();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_oplist.add(oplist102.getTree());
					// AST REWRITE
					// elements: oplist
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 228:11: -> ^( OP_ARGUMENTS[$lc, \"arguments\"] oplist )
					{
						// ghidra/sleigh/grammar/SleighParser.g:228:14: ^( OP_ARGUMENTS[$lc, \"arguments\"] oplist )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ARGUMENTS, lc, "arguments"), root_1);
						adaptor.addChild(root_1, stream_oplist.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:229:4: 
					{
					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 229:4: -> ^( OP_EMPTY_LIST[$lc, \"no arguments\"] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:229:7: ^( OP_EMPTY_LIST[$lc, \"no arguments\"] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_EMPTY_LIST, lc, "no arguments"), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "arguments"


	public static class oplist_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "oplist"
	// ghidra/sleigh/grammar/SleighParser.g:232:1: oplist : identifier ( COMMA ! identifier )* ;
	public final SleighParser.oplist_return oplist() throws RecognitionException {
		SleighParser.oplist_return retval = new SleighParser.oplist_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token COMMA104=null;
		ParserRuleReturnScope identifier103 =null;
		ParserRuleReturnScope identifier105 =null;

		CommonTree COMMA104_tree=null;

		try {
			// ghidra/sleigh/grammar/SleighParser.g:233:2: ( identifier ( COMMA ! identifier )* )
			// ghidra/sleigh/grammar/SleighParser.g:233:4: identifier ( COMMA ! identifier )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_identifier_in_oplist1484);
			identifier103=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier103.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:233:15: ( COMMA ! identifier )*
			loop27:
			while (true) {
				int alt27=2;
				int LA27_0 = input.LA(1);
				if ( (LA27_0==COMMA) ) {
					alt27=1;
				}

				switch (alt27) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:233:16: COMMA ! identifier
					{
					COMMA104=(Token)match(input,COMMA,FOLLOW_COMMA_in_oplist1487); if (state.failed) return retval;
					pushFollow(FOLLOW_identifier_in_oplist1490);
					identifier105=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier105.getTree());

					}
					break;

				default :
					break loop27;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "oplist"


	public static class withblock_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "withblock"
	// ghidra/sleigh/grammar/SleighParser.g:236:1: withblock : lc= RES_WITH id_or_nil COLON bitpat_or_nil contextblock LBRACE constructorlikelist RBRACE -> ^( OP_WITH[$lc, \"with\"] id_or_nil bitpat_or_nil contextblock constructorlikelist ) ;
	public final SleighParser.withblock_return withblock() throws RecognitionException {
		SleighParser.withblock_return retval = new SleighParser.withblock_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token COLON107=null;
		Token LBRACE110=null;
		Token RBRACE112=null;
		ParserRuleReturnScope id_or_nil106 =null;
		ParserRuleReturnScope bitpat_or_nil108 =null;
		ParserRuleReturnScope contextblock109 =null;
		ParserRuleReturnScope constructorlikelist111 =null;

		CommonTree lc_tree=null;
		CommonTree COLON107_tree=null;
		CommonTree LBRACE110_tree=null;
		CommonTree RBRACE112_tree=null;
		RewriteRuleTokenStream stream_RBRACE=new RewriteRuleTokenStream(adaptor,"token RBRACE");
		RewriteRuleTokenStream stream_RES_WITH=new RewriteRuleTokenStream(adaptor,"token RES_WITH");
		RewriteRuleTokenStream stream_COLON=new RewriteRuleTokenStream(adaptor,"token COLON");
		RewriteRuleTokenStream stream_LBRACE=new RewriteRuleTokenStream(adaptor,"token LBRACE");
		RewriteRuleSubtreeStream stream_bitpat_or_nil=new RewriteRuleSubtreeStream(adaptor,"rule bitpat_or_nil");
		RewriteRuleSubtreeStream stream_contextblock=new RewriteRuleSubtreeStream(adaptor,"rule contextblock");
		RewriteRuleSubtreeStream stream_constructorlikelist=new RewriteRuleSubtreeStream(adaptor,"rule constructorlikelist");
		RewriteRuleSubtreeStream stream_id_or_nil=new RewriteRuleSubtreeStream(adaptor,"rule id_or_nil");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:237:2: (lc= RES_WITH id_or_nil COLON bitpat_or_nil contextblock LBRACE constructorlikelist RBRACE -> ^( OP_WITH[$lc, \"with\"] id_or_nil bitpat_or_nil contextblock constructorlikelist ) )
			// ghidra/sleigh/grammar/SleighParser.g:237:4: lc= RES_WITH id_or_nil COLON bitpat_or_nil contextblock LBRACE constructorlikelist RBRACE
			{
			lc=(Token)match(input,RES_WITH,FOLLOW_RES_WITH_in_withblock1505); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RES_WITH.add(lc);

			pushFollow(FOLLOW_id_or_nil_in_withblock1507);
			id_or_nil106=id_or_nil();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_id_or_nil.add(id_or_nil106.getTree());
			COLON107=(Token)match(input,COLON,FOLLOW_COLON_in_withblock1509); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_COLON.add(COLON107);

			pushFollow(FOLLOW_bitpat_or_nil_in_withblock1511);
			bitpat_or_nil108=bitpat_or_nil();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_bitpat_or_nil.add(bitpat_or_nil108.getTree());
			pushFollow(FOLLOW_contextblock_in_withblock1513);
			contextblock109=contextblock();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_contextblock.add(contextblock109.getTree());
			LBRACE110=(Token)match(input,LBRACE,FOLLOW_LBRACE_in_withblock1515); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_LBRACE.add(LBRACE110);

			pushFollow(FOLLOW_constructorlikelist_in_withblock1517);
			constructorlikelist111=constructorlikelist();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_constructorlikelist.add(constructorlikelist111.getTree());
			RBRACE112=(Token)match(input,RBRACE,FOLLOW_RBRACE_in_withblock1519); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RBRACE.add(RBRACE112);

			// AST REWRITE
			// elements: bitpat_or_nil, constructorlikelist, id_or_nil, contextblock
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 238:4: -> ^( OP_WITH[$lc, \"with\"] id_or_nil bitpat_or_nil contextblock constructorlikelist )
			{
				// ghidra/sleigh/grammar/SleighParser.g:238:7: ^( OP_WITH[$lc, \"with\"] id_or_nil bitpat_or_nil contextblock constructorlikelist )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_WITH, lc, "with"), root_1);
				adaptor.addChild(root_1, stream_id_or_nil.nextTree());
				adaptor.addChild(root_1, stream_bitpat_or_nil.nextTree());
				adaptor.addChild(root_1, stream_contextblock.nextTree());
				adaptor.addChild(root_1, stream_constructorlikelist.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "withblock"


	public static class id_or_nil_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "id_or_nil"
	// ghidra/sleigh/grammar/SleighParser.g:241:1: id_or_nil : ( identifier | -> ^( OP_NIL ) );
	public final SleighParser.id_or_nil_return id_or_nil() throws RecognitionException {
		SleighParser.id_or_nil_return retval = new SleighParser.id_or_nil_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier113 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:242:2: ( identifier | -> ^( OP_NIL ) )
			int alt28=2;
			int LA28_0 = input.LA(1);
			if ( ((LA28_0 >= IDENTIFIER && LA28_0 <= KEY_WORDSIZE)) ) {
				alt28=1;
			}
			else if ( (LA28_0==COLON) ) {
				alt28=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 28, 0, input);
				throw nvae;
			}

			switch (alt28) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:242:4: identifier
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_identifier_in_id_or_nil1548);
					identifier113=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier113.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:243:4: 
					{
					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 243:4: -> ^( OP_NIL )
					{
						// ghidra/sleigh/grammar/SleighParser.g:243:7: ^( OP_NIL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NIL, "OP_NIL"), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "id_or_nil"


	public static class bitpat_or_nil_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "bitpat_or_nil"
	// ghidra/sleigh/grammar/SleighParser.g:246:1: bitpat_or_nil : ( bitpattern | -> ^( OP_NIL ) );
	public final SleighParser.bitpat_or_nil_return bitpat_or_nil() throws RecognitionException {
		SleighParser.bitpat_or_nil_return retval = new SleighParser.bitpat_or_nil_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope bitpattern114 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:247:2: ( bitpattern | -> ^( OP_NIL ) )
			int alt29=2;
			int LA29_0 = input.LA(1);
			if ( (LA29_0==ELLIPSIS||(LA29_0 >= IDENTIFIER && LA29_0 <= KEY_WORDSIZE)||LA29_0==LPAREN) ) {
				alt29=1;
			}
			else if ( ((LA29_0 >= LBRACE && LA29_0 <= LBRACKET)) ) {
				alt29=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 29, 0, input);
				throw nvae;
			}

			switch (alt29) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:247:4: bitpattern
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_bitpattern_in_bitpat_or_nil1568);
					bitpattern114=bitpattern();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, bitpattern114.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:248:4: 
					{
					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 248:4: -> ^( OP_NIL )
					{
						// ghidra/sleigh/grammar/SleighParser.g:248:7: ^( OP_NIL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NIL, "OP_NIL"), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "bitpat_or_nil"


	public static class def_or_conslike_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "def_or_conslike"
	// ghidra/sleigh/grammar/SleighParser.g:251:1: def_or_conslike : ( definition | constructorlike );
	public final SleighParser.def_or_conslike_return def_or_conslike() throws RecognitionException {
		SleighParser.def_or_conslike_return retval = new SleighParser.def_or_conslike_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope definition115 =null;
		ParserRuleReturnScope constructorlike116 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:252:2: ( definition | constructorlike )
			int alt30=2;
			switch ( input.LA(1) ) {
			case KEY_DEFINE:
				{
				int LA30_1 = input.LA(2);
				if ( ((LA30_1 >= IDENTIFIER && LA30_1 <= KEY_WORDSIZE)) ) {
					alt30=1;
				}
				else if ( (LA30_1==COLON) ) {
					alt30=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA30_2 = input.LA(2);
				if ( (LA30_2==KEY_NAMES||(LA30_2 >= KEY_VALUES && LA30_2 <= KEY_VARIABLES)) ) {
					alt30=1;
				}
				else if ( (LA30_2==COLON) ) {
					alt30=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case COLON:
			case IDENTIFIER:
			case KEY_ALIGNMENT:
			case KEY_BIG:
			case KEY_BITRANGE:
			case KEY_BUILD:
			case KEY_CALL:
			case KEY_CONTEXT:
			case KEY_CROSSBUILD:
			case KEY_DEC:
			case KEY_DEFAULT:
			case KEY_ENDIAN:
			case KEY_EXPORT:
			case KEY_GOTO:
			case KEY_HEX:
			case KEY_LITTLE:
			case KEY_LOCAL:
			case KEY_MACRO:
			case KEY_NAMES:
			case KEY_NOFLOW:
			case KEY_OFFSET:
			case KEY_PCODEOP:
			case KEY_RETURN:
			case KEY_SIGNED:
			case KEY_SIZE:
			case KEY_SPACE:
			case KEY_TOKEN:
			case KEY_TYPE:
			case KEY_UNIMPL:
			case KEY_VALUES:
			case KEY_VARIABLES:
			case KEY_WORDSIZE:
			case RES_WITH:
				{
				alt30=2;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 30, 0, input);
				throw nvae;
			}
			switch (alt30) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:252:4: definition
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_definition_in_def_or_conslike1588);
					definition115=definition();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, definition115.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:253:4: constructorlike
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_constructorlike_in_def_or_conslike1593);
					constructorlike116=constructorlike();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, constructorlike116.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "def_or_conslike"


	public static class constructorlikelist_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "constructorlikelist"
	// ghidra/sleigh/grammar/SleighParser.g:256:1: constructorlikelist : ( def_or_conslike )* -> ^( OP_CTLIST ( def_or_conslike )* ) ;
	public final SleighParser.constructorlikelist_return constructorlikelist() throws RecognitionException {
		SleighParser.constructorlikelist_return retval = new SleighParser.constructorlikelist_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope def_or_conslike117 =null;

		RewriteRuleSubtreeStream stream_def_or_conslike=new RewriteRuleSubtreeStream(adaptor,"rule def_or_conslike");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:257:2: ( ( def_or_conslike )* -> ^( OP_CTLIST ( def_or_conslike )* ) )
			// ghidra/sleigh/grammar/SleighParser.g:257:4: ( def_or_conslike )*
			{
			// ghidra/sleigh/grammar/SleighParser.g:257:4: ( def_or_conslike )*
			loop31:
			while (true) {
				int alt31=2;
				int LA31_0 = input.LA(1);
				if ( (LA31_0==COLON||(LA31_0 >= IDENTIFIER && LA31_0 <= KEY_WORDSIZE)||LA31_0==RES_WITH) ) {
					alt31=1;
				}

				switch (alt31) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:257:4: def_or_conslike
					{
					pushFollow(FOLLOW_def_or_conslike_in_constructorlikelist1604);
					def_or_conslike117=def_or_conslike();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_def_or_conslike.add(def_or_conslike117.getTree());
					}
					break;

				default :
					break loop31;
				}
			}

			// AST REWRITE
			// elements: def_or_conslike
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 257:21: -> ^( OP_CTLIST ( def_or_conslike )* )
			{
				// ghidra/sleigh/grammar/SleighParser.g:257:24: ^( OP_CTLIST ( def_or_conslike )* )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_CTLIST, "OP_CTLIST"), root_1);
				// ghidra/sleigh/grammar/SleighParser.g:257:36: ( def_or_conslike )*
				while ( stream_def_or_conslike.hasNext() ) {
					adaptor.addChild(root_1, stream_def_or_conslike.nextTree());
				}
				stream_def_or_conslike.reset();

				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "constructorlikelist"


	public static class constructor_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "constructor"
	// ghidra/sleigh/grammar/SleighParser.g:260:1: constructor : ctorstart bitpattern contextblock ctorsemantic -> ^( OP_CONSTRUCTOR ctorstart bitpattern contextblock ctorsemantic ) ;
	public final SleighParser.constructor_return constructor() throws RecognitionException {
		SleighParser.constructor_return retval = new SleighParser.constructor_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope ctorstart118 =null;
		ParserRuleReturnScope bitpattern119 =null;
		ParserRuleReturnScope contextblock120 =null;
		ParserRuleReturnScope ctorsemantic121 =null;

		RewriteRuleSubtreeStream stream_bitpattern=new RewriteRuleSubtreeStream(adaptor,"rule bitpattern");
		RewriteRuleSubtreeStream stream_ctorsemantic=new RewriteRuleSubtreeStream(adaptor,"rule ctorsemantic");
		RewriteRuleSubtreeStream stream_contextblock=new RewriteRuleSubtreeStream(adaptor,"rule contextblock");
		RewriteRuleSubtreeStream stream_ctorstart=new RewriteRuleSubtreeStream(adaptor,"rule ctorstart");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:261:2: ( ctorstart bitpattern contextblock ctorsemantic -> ^( OP_CONSTRUCTOR ctorstart bitpattern contextblock ctorsemantic ) )
			// ghidra/sleigh/grammar/SleighParser.g:261:4: ctorstart bitpattern contextblock ctorsemantic
			{
			pushFollow(FOLLOW_ctorstart_in_constructor1626);
			ctorstart118=ctorstart();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_ctorstart.add(ctorstart118.getTree());
			pushFollow(FOLLOW_bitpattern_in_constructor1628);
			bitpattern119=bitpattern();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_bitpattern.add(bitpattern119.getTree());
			pushFollow(FOLLOW_contextblock_in_constructor1630);
			contextblock120=contextblock();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_contextblock.add(contextblock120.getTree());
			pushFollow(FOLLOW_ctorsemantic_in_constructor1632);
			ctorsemantic121=ctorsemantic();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_ctorsemantic.add(ctorsemantic121.getTree());
			// AST REWRITE
			// elements: ctorstart, bitpattern, contextblock, ctorsemantic
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 261:51: -> ^( OP_CONSTRUCTOR ctorstart bitpattern contextblock ctorsemantic )
			{
				// ghidra/sleigh/grammar/SleighParser.g:261:54: ^( OP_CONSTRUCTOR ctorstart bitpattern contextblock ctorsemantic )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_CONSTRUCTOR, "OP_CONSTRUCTOR"), root_1);
				adaptor.addChild(root_1, stream_ctorstart.nextTree());
				adaptor.addChild(root_1, stream_bitpattern.nextTree());
				adaptor.addChild(root_1, stream_contextblock.nextTree());
				adaptor.addChild(root_1, stream_ctorsemantic.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "constructor"


	public static class ctorsemantic_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "ctorsemantic"
	// ghidra/sleigh/grammar/SleighParser.g:264:1: ctorsemantic : ( semanticbody -> ^( OP_PCODE semanticbody ) |lc= KEY_UNIMPL -> ^( OP_PCODE[$lc] OP_UNIMPL[$lc] ) );
	public final SleighParser.ctorsemantic_return ctorsemantic() throws RecognitionException {
		SleighParser.ctorsemantic_return retval = new SleighParser.ctorsemantic_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope semanticbody122 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_UNIMPL=new RewriteRuleTokenStream(adaptor,"token KEY_UNIMPL");
		RewriteRuleSubtreeStream stream_semanticbody=new RewriteRuleSubtreeStream(adaptor,"rule semanticbody");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:265:2: ( semanticbody -> ^( OP_PCODE semanticbody ) |lc= KEY_UNIMPL -> ^( OP_PCODE[$lc] OP_UNIMPL[$lc] ) )
			int alt32=2;
			int LA32_0 = input.LA(1);
			if ( (LA32_0==LBRACE) ) {
				alt32=1;
			}
			else if ( (LA32_0==KEY_UNIMPL) ) {
				alt32=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 32, 0, input);
				throw nvae;
			}

			switch (alt32) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:265:4: semanticbody
					{
					pushFollow(FOLLOW_semanticbody_in_ctorsemantic1657);
					semanticbody122=semanticbody();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_semanticbody.add(semanticbody122.getTree());
					// AST REWRITE
					// elements: semanticbody
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 265:17: -> ^( OP_PCODE semanticbody )
					{
						// ghidra/sleigh/grammar/SleighParser.g:265:20: ^( OP_PCODE semanticbody )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PCODE, "OP_PCODE"), root_1);
						adaptor.addChild(root_1, stream_semanticbody.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:266:4: lc= KEY_UNIMPL
					{
					lc=(Token)match(input,KEY_UNIMPL,FOLLOW_KEY_UNIMPL_in_ctorsemantic1672); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_UNIMPL.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 266:18: -> ^( OP_PCODE[$lc] OP_UNIMPL[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:266:21: ^( OP_PCODE[$lc] OP_UNIMPL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PCODE, lc), root_1);
						adaptor.addChild(root_1, (CommonTree)adaptor.create(OP_UNIMPL, lc));
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "ctorsemantic"


	public static class bitpattern_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "bitpattern"
	// ghidra/sleigh/grammar/SleighParser.g:269:1: bitpattern : pequation -> ^( OP_BIT_PATTERN pequation ) ;
	public final SleighParser.bitpattern_return bitpattern() throws RecognitionException {
		SleighParser.bitpattern_return retval = new SleighParser.bitpattern_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pequation123 =null;

		RewriteRuleSubtreeStream stream_pequation=new RewriteRuleSubtreeStream(adaptor,"rule pequation");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:270:2: ( pequation -> ^( OP_BIT_PATTERN pequation ) )
			// ghidra/sleigh/grammar/SleighParser.g:270:4: pequation
			{
			pushFollow(FOLLOW_pequation_in_bitpattern1693);
			pequation123=pequation();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_pequation.add(pequation123.getTree());
			// AST REWRITE
			// elements: pequation
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 270:14: -> ^( OP_BIT_PATTERN pequation )
			{
				// ghidra/sleigh/grammar/SleighParser.g:270:17: ^( OP_BIT_PATTERN pequation )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BIT_PATTERN, "OP_BIT_PATTERN"), root_1);
				adaptor.addChild(root_1, stream_pequation.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "bitpattern"


	public static class ctorstart_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "ctorstart"
	// ghidra/sleigh/grammar/SleighParser.g:273:1: ctorstart : ( identifier display -> ^( OP_SUBTABLE identifier display ) | display -> ^( OP_TABLE display ) );
	public final SleighParser.ctorstart_return ctorstart() throws RecognitionException {
		SleighParser.ctorstart_return retval = new SleighParser.ctorstart_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier124 =null;
		ParserRuleReturnScope display125 =null;
		ParserRuleReturnScope display126 =null;

		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_display=new RewriteRuleSubtreeStream(adaptor,"rule display");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:274:2: ( identifier display -> ^( OP_SUBTABLE identifier display ) | display -> ^( OP_TABLE display ) )
			int alt33=2;
			int LA33_0 = input.LA(1);
			if ( ((LA33_0 >= IDENTIFIER && LA33_0 <= KEY_WORDSIZE)) ) {
				alt33=1;
			}
			else if ( (LA33_0==COLON) ) {
				alt33=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 33, 0, input);
				throw nvae;
			}

			switch (alt33) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:274:4: identifier display
					{
					pushFollow(FOLLOW_identifier_in_ctorstart1712);
					identifier124=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_identifier.add(identifier124.getTree());
					pushFollow(FOLLOW_display_in_ctorstart1714);
					display125=display();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_display.add(display125.getTree());
					// AST REWRITE
					// elements: display, identifier
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 274:23: -> ^( OP_SUBTABLE identifier display )
					{
						// ghidra/sleigh/grammar/SleighParser.g:274:26: ^( OP_SUBTABLE identifier display )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SUBTABLE, "OP_SUBTABLE"), root_1);
						adaptor.addChild(root_1, stream_identifier.nextTree());
						adaptor.addChild(root_1, stream_display.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:275:4: display
					{
					pushFollow(FOLLOW_display_in_ctorstart1729);
					display126=display();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_display.add(display126.getTree());
					// AST REWRITE
					// elements: display
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 275:12: -> ^( OP_TABLE display )
					{
						// ghidra/sleigh/grammar/SleighParser.g:275:15: ^( OP_TABLE display )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_TABLE, "OP_TABLE"), root_1);
						adaptor.addChild(root_1, stream_display.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "ctorstart"


	public static class contextblock_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "contextblock"
	// ghidra/sleigh/grammar/SleighParser.g:278:1: contextblock : (lc= LBRACKET ctxstmts RBRACKET -> ^( OP_CONTEXT_BLOCK[$lc, \"[...]\"] ctxstmts ) | -> ^( OP_NO_CONTEXT_BLOCK ) );
	public final SleighParser.contextblock_return contextblock() throws RecognitionException {
		SleighParser.contextblock_return retval = new SleighParser.contextblock_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token RBRACKET128=null;
		ParserRuleReturnScope ctxstmts127 =null;

		CommonTree lc_tree=null;
		CommonTree RBRACKET128_tree=null;
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleSubtreeStream stream_ctxstmts=new RewriteRuleSubtreeStream(adaptor,"rule ctxstmts");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:279:2: (lc= LBRACKET ctxstmts RBRACKET -> ^( OP_CONTEXT_BLOCK[$lc, \"[...]\"] ctxstmts ) | -> ^( OP_NO_CONTEXT_BLOCK ) )
			int alt34=2;
			int LA34_0 = input.LA(1);
			if ( (LA34_0==LBRACKET) ) {
				alt34=1;
			}
			else if ( (LA34_0==KEY_UNIMPL||LA34_0==LBRACE) ) {
				alt34=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 34, 0, input);
				throw nvae;
			}

			switch (alt34) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:279:4: lc= LBRACKET ctxstmts RBRACKET
					{
					lc=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_contextblock1750); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LBRACKET.add(lc);

					pushFollow(FOLLOW_ctxstmts_in_contextblock1752);
					ctxstmts127=ctxstmts();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_ctxstmts.add(ctxstmts127.getTree());
					RBRACKET128=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_contextblock1754); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RBRACKET.add(RBRACKET128);

					// AST REWRITE
					// elements: ctxstmts
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 279:34: -> ^( OP_CONTEXT_BLOCK[$lc, \"[...]\"] ctxstmts )
					{
						// ghidra/sleigh/grammar/SleighParser.g:279:37: ^( OP_CONTEXT_BLOCK[$lc, \"[...]\"] ctxstmts )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_CONTEXT_BLOCK, lc, "[...]"), root_1);
						adaptor.addChild(root_1, stream_ctxstmts.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:280:4: 
					{
					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 280:4: -> ^( OP_NO_CONTEXT_BLOCK )
					{
						// ghidra/sleigh/grammar/SleighParser.g:280:7: ^( OP_NO_CONTEXT_BLOCK )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NO_CONTEXT_BLOCK, "OP_NO_CONTEXT_BLOCK"), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "contextblock"


	public static class ctxstmts_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "ctxstmts"
	// ghidra/sleigh/grammar/SleighParser.g:283:1: ctxstmts : ( ctxstmt )* ;
	public final SleighParser.ctxstmts_return ctxstmts() throws RecognitionException {
		SleighParser.ctxstmts_return retval = new SleighParser.ctxstmts_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope ctxstmt129 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:284:2: ( ( ctxstmt )* )
			// ghidra/sleigh/grammar/SleighParser.g:284:4: ( ctxstmt )*
			{
			root_0 = (CommonTree)adaptor.nil();


			// ghidra/sleigh/grammar/SleighParser.g:284:4: ( ctxstmt )*
			loop35:
			while (true) {
				int alt35=2;
				int LA35_0 = input.LA(1);
				if ( ((LA35_0 >= IDENTIFIER && LA35_0 <= KEY_WORDSIZE)) ) {
					alt35=1;
				}

				switch (alt35) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:284:4: ctxstmt
					{
					pushFollow(FOLLOW_ctxstmt_in_ctxstmts1783);
					ctxstmt129=ctxstmt();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, ctxstmt129.getTree());

					}
					break;

				default :
					break loop35;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "ctxstmts"


	public static class ctxstmt_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "ctxstmt"
	// ghidra/sleigh/grammar/SleighParser.g:287:1: ctxstmt : ( ctxassign SEMI !| pfuncall SEMI !);
	public final SleighParser.ctxstmt_return ctxstmt() throws RecognitionException {
		SleighParser.ctxstmt_return retval = new SleighParser.ctxstmt_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token SEMI131=null;
		Token SEMI133=null;
		ParserRuleReturnScope ctxassign130 =null;
		ParserRuleReturnScope pfuncall132 =null;

		CommonTree SEMI131_tree=null;
		CommonTree SEMI133_tree=null;

		try {
			// ghidra/sleigh/grammar/SleighParser.g:288:2: ( ctxassign SEMI !| pfuncall SEMI !)
			int alt36=2;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
				{
				int LA36_1 = input.LA(2);
				if ( (LA36_1==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_1==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ALIGNMENT:
				{
				int LA36_2 = input.LA(2);
				if ( (LA36_2==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_2==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA36_3 = input.LA(2);
				if ( (LA36_3==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_3==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BIG:
				{
				int LA36_4 = input.LA(2);
				if ( (LA36_4==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_4==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 4, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BITRANGE:
				{
				int LA36_5 = input.LA(2);
				if ( (LA36_5==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_5==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 5, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BUILD:
				{
				int LA36_6 = input.LA(2);
				if ( (LA36_6==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_6==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 6, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CALL:
				{
				int LA36_7 = input.LA(2);
				if ( (LA36_7==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_7==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 7, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CONTEXT:
				{
				int LA36_8 = input.LA(2);
				if ( (LA36_8==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_8==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 8, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CROSSBUILD:
				{
				int LA36_9 = input.LA(2);
				if ( (LA36_9==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_9==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 9, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEC:
				{
				int LA36_10 = input.LA(2);
				if ( (LA36_10==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_10==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 10, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFAULT:
				{
				int LA36_11 = input.LA(2);
				if ( (LA36_11==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_11==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 11, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFINE:
				{
				int LA36_12 = input.LA(2);
				if ( (LA36_12==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_12==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 12, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ENDIAN:
				{
				int LA36_13 = input.LA(2);
				if ( (LA36_13==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_13==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 13, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_EXPORT:
				{
				int LA36_14 = input.LA(2);
				if ( (LA36_14==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_14==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 14, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_GOTO:
				{
				int LA36_15 = input.LA(2);
				if ( (LA36_15==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_15==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 15, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_HEX:
				{
				int LA36_16 = input.LA(2);
				if ( (LA36_16==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_16==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 16, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LITTLE:
				{
				int LA36_17 = input.LA(2);
				if ( (LA36_17==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_17==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 17, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LOCAL:
				{
				int LA36_18 = input.LA(2);
				if ( (LA36_18==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_18==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 18, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_MACRO:
				{
				int LA36_19 = input.LA(2);
				if ( (LA36_19==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_19==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 19, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NAMES:
				{
				int LA36_20 = input.LA(2);
				if ( (LA36_20==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_20==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 20, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA36_21 = input.LA(2);
				if ( (LA36_21==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_21==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 21, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_OFFSET:
				{
				int LA36_22 = input.LA(2);
				if ( (LA36_22==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_22==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 22, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_PCODEOP:
				{
				int LA36_23 = input.LA(2);
				if ( (LA36_23==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_23==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 23, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_RETURN:
				{
				int LA36_24 = input.LA(2);
				if ( (LA36_24==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_24==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 24, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIGNED:
				{
				int LA36_25 = input.LA(2);
				if ( (LA36_25==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_25==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 25, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIZE:
				{
				int LA36_26 = input.LA(2);
				if ( (LA36_26==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_26==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 26, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SPACE:
				{
				int LA36_27 = input.LA(2);
				if ( (LA36_27==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_27==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 27, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TOKEN:
				{
				int LA36_28 = input.LA(2);
				if ( (LA36_28==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_28==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 28, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TYPE:
				{
				int LA36_29 = input.LA(2);
				if ( (LA36_29==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_29==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 29, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_UNIMPL:
				{
				int LA36_30 = input.LA(2);
				if ( (LA36_30==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_30==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 30, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VALUES:
				{
				int LA36_31 = input.LA(2);
				if ( (LA36_31==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_31==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 31, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VARIABLES:
				{
				int LA36_32 = input.LA(2);
				if ( (LA36_32==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_32==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 32, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_WORDSIZE:
				{
				int LA36_33 = input.LA(2);
				if ( (LA36_33==ASSIGN) ) {
					alt36=1;
				}
				else if ( (LA36_33==LPAREN) ) {
					alt36=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 36, 33, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 36, 0, input);
				throw nvae;
			}
			switch (alt36) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:288:4: ctxassign SEMI !
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_ctxassign_in_ctxstmt1795);
					ctxassign130=ctxassign();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, ctxassign130.getTree());

					SEMI131=(Token)match(input,SEMI,FOLLOW_SEMI_in_ctxstmt1797); if (state.failed) return retval;
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:289:4: pfuncall SEMI !
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pfuncall_in_ctxstmt1803);
					pfuncall132=pfuncall();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pfuncall132.getTree());

					SEMI133=(Token)match(input,SEMI,FOLLOW_SEMI_in_ctxstmt1805); if (state.failed) return retval;
					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "ctxstmt"


	public static class ctxassign_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "ctxassign"
	// ghidra/sleigh/grammar/SleighParser.g:292:1: ctxassign : ctxlval lc= ASSIGN pexpression -> ^( OP_ASSIGN[$lc] ctxlval pexpression ) ;
	public final SleighParser.ctxassign_return ctxassign() throws RecognitionException {
		SleighParser.ctxassign_return retval = new SleighParser.ctxassign_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope ctxlval134 =null;
		ParserRuleReturnScope pexpression135 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_pexpression=new RewriteRuleSubtreeStream(adaptor,"rule pexpression");
		RewriteRuleSubtreeStream stream_ctxlval=new RewriteRuleSubtreeStream(adaptor,"rule ctxlval");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:293:2: ( ctxlval lc= ASSIGN pexpression -> ^( OP_ASSIGN[$lc] ctxlval pexpression ) )
			// ghidra/sleigh/grammar/SleighParser.g:293:4: ctxlval lc= ASSIGN pexpression
			{
			pushFollow(FOLLOW_ctxlval_in_ctxassign1817);
			ctxlval134=ctxlval();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_ctxlval.add(ctxlval134.getTree());
			lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_ctxassign1821); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(lc);

			pushFollow(FOLLOW_pexpression_in_ctxassign1823);
			pexpression135=pexpression();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_pexpression.add(pexpression135.getTree());
			// AST REWRITE
			// elements: pexpression, ctxlval
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 293:34: -> ^( OP_ASSIGN[$lc] ctxlval pexpression )
			{
				// ghidra/sleigh/grammar/SleighParser.g:293:37: ^( OP_ASSIGN[$lc] ctxlval pexpression )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ASSIGN, lc), root_1);
				adaptor.addChild(root_1, stream_ctxlval.nextTree());
				adaptor.addChild(root_1, stream_pexpression.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "ctxassign"


	public static class ctxlval_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "ctxlval"
	// ghidra/sleigh/grammar/SleighParser.g:296:1: ctxlval : identifier ;
	public final SleighParser.ctxlval_return ctxlval() throws RecognitionException {
		SleighParser.ctxlval_return retval = new SleighParser.ctxlval_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier136 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:297:2: ( identifier )
			// ghidra/sleigh/grammar/SleighParser.g:297:4: identifier
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_identifier_in_ctxlval1845);
			identifier136=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier136.getTree());

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "ctxlval"


	public static class pfuncall_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pfuncall"
	// ghidra/sleigh/grammar/SleighParser.g:300:1: pfuncall : pexpression_apply ;
	public final SleighParser.pfuncall_return pfuncall() throws RecognitionException {
		SleighParser.pfuncall_return retval = new SleighParser.pfuncall_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_apply137 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:301:2: ( pexpression_apply )
			// ghidra/sleigh/grammar/SleighParser.g:301:4: pexpression_apply
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_apply_in_pfuncall1856);
			pexpression_apply137=pexpression_apply();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_apply137.getTree());

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pfuncall"


	public static class pequation_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation"
	// ghidra/sleigh/grammar/SleighParser.g:304:1: pequation : pequation_or ;
	public final SleighParser.pequation_return pequation() throws RecognitionException {
		SleighParser.pequation_return retval = new SleighParser.pequation_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pequation_or138 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:305:2: ( pequation_or )
			// ghidra/sleigh/grammar/SleighParser.g:305:4: pequation_or
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pequation_or_in_pequation1867);
			pequation_or138=pequation_or();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_or138.getTree());

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation"


	public static class pequation_or_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_or"
	// ghidra/sleigh/grammar/SleighParser.g:308:1: pequation_or : pequation_seq ( pequation_or_op ^ pequation_seq )* ;
	public final SleighParser.pequation_or_return pequation_or() throws RecognitionException {
		SleighParser.pequation_or_return retval = new SleighParser.pequation_or_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pequation_seq139 =null;
		ParserRuleReturnScope pequation_or_op140 =null;
		ParserRuleReturnScope pequation_seq141 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:309:2: ( pequation_seq ( pequation_or_op ^ pequation_seq )* )
			// ghidra/sleigh/grammar/SleighParser.g:309:4: pequation_seq ( pequation_or_op ^ pequation_seq )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pequation_seq_in_pequation_or1878);
			pequation_seq139=pequation_seq();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_seq139.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:309:18: ( pequation_or_op ^ pequation_seq )*
			loop37:
			while (true) {
				int alt37=2;
				int LA37_0 = input.LA(1);
				if ( (LA37_0==PIPE) ) {
					alt37=1;
				}

				switch (alt37) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:309:20: pequation_or_op ^ pequation_seq
					{
					pushFollow(FOLLOW_pequation_or_op_in_pequation_or1882);
					pequation_or_op140=pequation_or_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pequation_or_op140.getTree(), root_0);
					pushFollow(FOLLOW_pequation_seq_in_pequation_or1885);
					pequation_seq141=pequation_seq();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_seq141.getTree());

					}
					break;

				default :
					break loop37;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_or"


	public static class pequation_or_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_or_op"
	// ghidra/sleigh/grammar/SleighParser.g:312:1: pequation_or_op : lc= PIPE -> ^( OP_BOOL_OR[$lc] ) ;
	public final SleighParser.pequation_or_op_return pequation_or_op() throws RecognitionException {
		SleighParser.pequation_or_op_return retval = new SleighParser.pequation_or_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_PIPE=new RewriteRuleTokenStream(adaptor,"token PIPE");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:313:2: (lc= PIPE -> ^( OP_BOOL_OR[$lc] ) )
			// ghidra/sleigh/grammar/SleighParser.g:313:4: lc= PIPE
			{
			lc=(Token)match(input,PIPE,FOLLOW_PIPE_in_pequation_or_op1901); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_PIPE.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 313:12: -> ^( OP_BOOL_OR[$lc] )
			{
				// ghidra/sleigh/grammar/SleighParser.g:313:15: ^( OP_BOOL_OR[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BOOL_OR, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_or_op"


	public static class pequation_seq_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_seq"
	// ghidra/sleigh/grammar/SleighParser.g:316:1: pequation_seq : pequation_and ( pequation_seq_op ^ pequation_and )* ;
	public final SleighParser.pequation_seq_return pequation_seq() throws RecognitionException {
		SleighParser.pequation_seq_return retval = new SleighParser.pequation_seq_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pequation_and142 =null;
		ParserRuleReturnScope pequation_seq_op143 =null;
		ParserRuleReturnScope pequation_and144 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:317:2: ( pequation_and ( pequation_seq_op ^ pequation_and )* )
			// ghidra/sleigh/grammar/SleighParser.g:317:4: pequation_and ( pequation_seq_op ^ pequation_and )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pequation_and_in_pequation_seq1919);
			pequation_and142=pequation_and();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_and142.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:317:18: ( pequation_seq_op ^ pequation_and )*
			loop38:
			while (true) {
				int alt38=2;
				int LA38_0 = input.LA(1);
				if ( (LA38_0==SEMI) ) {
					alt38=1;
				}

				switch (alt38) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:317:20: pequation_seq_op ^ pequation_and
					{
					pushFollow(FOLLOW_pequation_seq_op_in_pequation_seq1923);
					pequation_seq_op143=pequation_seq_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pequation_seq_op143.getTree(), root_0);
					pushFollow(FOLLOW_pequation_and_in_pequation_seq1926);
					pequation_and144=pequation_and();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_and144.getTree());

					}
					break;

				default :
					break loop38;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_seq"


	public static class pequation_seq_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_seq_op"
	// ghidra/sleigh/grammar/SleighParser.g:320:1: pequation_seq_op : lc= SEMI -> ^( OP_SEQUENCE[$lc] ) ;
	public final SleighParser.pequation_seq_op_return pequation_seq_op() throws RecognitionException {
		SleighParser.pequation_seq_op_return retval = new SleighParser.pequation_seq_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SEMI=new RewriteRuleTokenStream(adaptor,"token SEMI");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:321:2: (lc= SEMI -> ^( OP_SEQUENCE[$lc] ) )
			// ghidra/sleigh/grammar/SleighParser.g:321:4: lc= SEMI
			{
			lc=(Token)match(input,SEMI,FOLLOW_SEMI_in_pequation_seq_op1942); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_SEMI.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 321:12: -> ^( OP_SEQUENCE[$lc] )
			{
				// ghidra/sleigh/grammar/SleighParser.g:321:15: ^( OP_SEQUENCE[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SEQUENCE, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_seq_op"


	public static class pequation_and_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_and"
	// ghidra/sleigh/grammar/SleighParser.g:324:1: pequation_and : pequation_ellipsis ( pequation_and_op ^ pequation_ellipsis )* ;
	public final SleighParser.pequation_and_return pequation_and() throws RecognitionException {
		SleighParser.pequation_and_return retval = new SleighParser.pequation_and_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pequation_ellipsis145 =null;
		ParserRuleReturnScope pequation_and_op146 =null;
		ParserRuleReturnScope pequation_ellipsis147 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:325:2: ( pequation_ellipsis ( pequation_and_op ^ pequation_ellipsis )* )
			// ghidra/sleigh/grammar/SleighParser.g:325:4: pequation_ellipsis ( pequation_and_op ^ pequation_ellipsis )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pequation_ellipsis_in_pequation_and1960);
			pequation_ellipsis145=pequation_ellipsis();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_ellipsis145.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:325:23: ( pequation_and_op ^ pequation_ellipsis )*
			loop39:
			while (true) {
				int alt39=2;
				int LA39_0 = input.LA(1);
				if ( (LA39_0==AMPERSAND) ) {
					alt39=1;
				}

				switch (alt39) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:325:25: pequation_and_op ^ pequation_ellipsis
					{
					pushFollow(FOLLOW_pequation_and_op_in_pequation_and1964);
					pequation_and_op146=pequation_and_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pequation_and_op146.getTree(), root_0);
					pushFollow(FOLLOW_pequation_ellipsis_in_pequation_and1967);
					pequation_ellipsis147=pequation_ellipsis();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_ellipsis147.getTree());

					}
					break;

				default :
					break loop39;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_and"


	public static class pequation_and_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_and_op"
	// ghidra/sleigh/grammar/SleighParser.g:328:1: pequation_and_op : lc= AMPERSAND -> ^( OP_BOOL_AND[$lc] ) ;
	public final SleighParser.pequation_and_op_return pequation_and_op() throws RecognitionException {
		SleighParser.pequation_and_op_return retval = new SleighParser.pequation_and_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_AMPERSAND=new RewriteRuleTokenStream(adaptor,"token AMPERSAND");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:329:2: (lc= AMPERSAND -> ^( OP_BOOL_AND[$lc] ) )
			// ghidra/sleigh/grammar/SleighParser.g:329:4: lc= AMPERSAND
			{
			lc=(Token)match(input,AMPERSAND,FOLLOW_AMPERSAND_in_pequation_and_op1983); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_AMPERSAND.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 329:17: -> ^( OP_BOOL_AND[$lc] )
			{
				// ghidra/sleigh/grammar/SleighParser.g:329:20: ^( OP_BOOL_AND[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BOOL_AND, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_and_op"


	public static class pequation_ellipsis_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_ellipsis"
	// ghidra/sleigh/grammar/SleighParser.g:332:1: pequation_ellipsis : (lc= ELLIPSIS pequation_ellipsis_right -> ^( OP_ELLIPSIS[$lc] pequation_ellipsis_right ) | pequation_ellipsis_right );
	public final SleighParser.pequation_ellipsis_return pequation_ellipsis() throws RecognitionException {
		SleighParser.pequation_ellipsis_return retval = new SleighParser.pequation_ellipsis_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope pequation_ellipsis_right148 =null;
		ParserRuleReturnScope pequation_ellipsis_right149 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_ELLIPSIS=new RewriteRuleTokenStream(adaptor,"token ELLIPSIS");
		RewriteRuleSubtreeStream stream_pequation_ellipsis_right=new RewriteRuleSubtreeStream(adaptor,"rule pequation_ellipsis_right");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:333:2: (lc= ELLIPSIS pequation_ellipsis_right -> ^( OP_ELLIPSIS[$lc] pequation_ellipsis_right ) | pequation_ellipsis_right )
			int alt40=2;
			int LA40_0 = input.LA(1);
			if ( (LA40_0==ELLIPSIS) ) {
				alt40=1;
			}
			else if ( ((LA40_0 >= IDENTIFIER && LA40_0 <= KEY_WORDSIZE)||LA40_0==LPAREN) ) {
				alt40=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 40, 0, input);
				throw nvae;
			}

			switch (alt40) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:333:4: lc= ELLIPSIS pequation_ellipsis_right
					{
					lc=(Token)match(input,ELLIPSIS,FOLLOW_ELLIPSIS_in_pequation_ellipsis2003); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_ELLIPSIS.add(lc);

					pushFollow(FOLLOW_pequation_ellipsis_right_in_pequation_ellipsis2005);
					pequation_ellipsis_right148=pequation_ellipsis_right();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_pequation_ellipsis_right.add(pequation_ellipsis_right148.getTree());
					// AST REWRITE
					// elements: pequation_ellipsis_right
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 333:41: -> ^( OP_ELLIPSIS[$lc] pequation_ellipsis_right )
					{
						// ghidra/sleigh/grammar/SleighParser.g:333:44: ^( OP_ELLIPSIS[$lc] pequation_ellipsis_right )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ELLIPSIS, lc), root_1);
						adaptor.addChild(root_1, stream_pequation_ellipsis_right.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:334:4: pequation_ellipsis_right
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pequation_ellipsis_right_in_pequation_ellipsis2019);
					pequation_ellipsis_right149=pequation_ellipsis_right();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_ellipsis_right149.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_ellipsis"


	public static class pequation_ellipsis_right_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_ellipsis_right"
	// ghidra/sleigh/grammar/SleighParser.g:337:1: pequation_ellipsis_right : ( ( pequation_atomic ELLIPSIS )=> pequation_atomic lc= ELLIPSIS -> ^( OP_ELLIPSIS_RIGHT[$lc] pequation_atomic ) | pequation_atomic );
	public final SleighParser.pequation_ellipsis_right_return pequation_ellipsis_right() throws RecognitionException {
		SleighParser.pequation_ellipsis_right_return retval = new SleighParser.pequation_ellipsis_right_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope pequation_atomic150 =null;
		ParserRuleReturnScope pequation_atomic151 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_ELLIPSIS=new RewriteRuleTokenStream(adaptor,"token ELLIPSIS");
		RewriteRuleSubtreeStream stream_pequation_atomic=new RewriteRuleSubtreeStream(adaptor,"rule pequation_atomic");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:338:2: ( ( pequation_atomic ELLIPSIS )=> pequation_atomic lc= ELLIPSIS -> ^( OP_ELLIPSIS_RIGHT[$lc] pequation_atomic ) | pequation_atomic )
			int alt41=2;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
				{
				int LA41_1 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_ALIGNMENT:
				{
				int LA41_2 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA41_3 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_BIG:
				{
				int LA41_4 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_BITRANGE:
				{
				int LA41_5 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_BUILD:
				{
				int LA41_6 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_CALL:
				{
				int LA41_7 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_CONTEXT:
				{
				int LA41_8 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_CROSSBUILD:
				{
				int LA41_9 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_DEC:
				{
				int LA41_10 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_DEFAULT:
				{
				int LA41_11 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_DEFINE:
				{
				int LA41_12 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_ENDIAN:
				{
				int LA41_13 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_EXPORT:
				{
				int LA41_14 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_GOTO:
				{
				int LA41_15 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_HEX:
				{
				int LA41_16 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_LITTLE:
				{
				int LA41_17 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_LOCAL:
				{
				int LA41_18 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_MACRO:
				{
				int LA41_19 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_NAMES:
				{
				int LA41_20 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA41_21 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_OFFSET:
				{
				int LA41_22 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_PCODEOP:
				{
				int LA41_23 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_RETURN:
				{
				int LA41_24 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_SIGNED:
				{
				int LA41_25 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_SIZE:
				{
				int LA41_26 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_SPACE:
				{
				int LA41_27 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_TOKEN:
				{
				int LA41_28 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_TYPE:
				{
				int LA41_29 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_UNIMPL:
				{
				int LA41_30 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_VALUES:
				{
				int LA41_31 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_VARIABLES:
				{
				int LA41_32 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case KEY_WORDSIZE:
				{
				int LA41_33 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			case LPAREN:
				{
				int LA41_34 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt41=1;
				}
				else if ( (true) ) {
					alt41=2;
				}

				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 41, 0, input);
				throw nvae;
			}
			switch (alt41) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:338:4: ( pequation_atomic ELLIPSIS )=> pequation_atomic lc= ELLIPSIS
					{
					pushFollow(FOLLOW_pequation_atomic_in_pequation_ellipsis_right2037);
					pequation_atomic150=pequation_atomic();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_pequation_atomic.add(pequation_atomic150.getTree());
					lc=(Token)match(input,ELLIPSIS,FOLLOW_ELLIPSIS_in_pequation_ellipsis_right2041); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_ELLIPSIS.add(lc);

					// AST REWRITE
					// elements: pequation_atomic
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 338:63: -> ^( OP_ELLIPSIS_RIGHT[$lc] pequation_atomic )
					{
						// ghidra/sleigh/grammar/SleighParser.g:338:66: ^( OP_ELLIPSIS_RIGHT[$lc] pequation_atomic )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ELLIPSIS_RIGHT, lc), root_1);
						adaptor.addChild(root_1, stream_pequation_atomic.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:339:4: pequation_atomic
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pequation_atomic_in_pequation_ellipsis_right2055);
					pequation_atomic151=pequation_atomic();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_atomic151.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_ellipsis_right"


	public static class pequation_atomic_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_atomic"
	// ghidra/sleigh/grammar/SleighParser.g:342:1: pequation_atomic : ( constraint |lc= LPAREN pequation RPAREN -> ^( OP_PARENTHESIZED[$lc,\"(...)\"] pequation ) );
	public final SleighParser.pequation_atomic_return pequation_atomic() throws RecognitionException {
		SleighParser.pequation_atomic_return retval = new SleighParser.pequation_atomic_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token RPAREN154=null;
		ParserRuleReturnScope constraint152 =null;
		ParserRuleReturnScope pequation153 =null;

		CommonTree lc_tree=null;
		CommonTree RPAREN154_tree=null;
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleSubtreeStream stream_pequation=new RewriteRuleSubtreeStream(adaptor,"rule pequation");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:343:2: ( constraint |lc= LPAREN pequation RPAREN -> ^( OP_PARENTHESIZED[$lc,\"(...)\"] pequation ) )
			int alt42=2;
			int LA42_0 = input.LA(1);
			if ( ((LA42_0 >= IDENTIFIER && LA42_0 <= KEY_WORDSIZE)) ) {
				alt42=1;
			}
			else if ( (LA42_0==LPAREN) ) {
				alt42=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 42, 0, input);
				throw nvae;
			}

			switch (alt42) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:343:4: constraint
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_constraint_in_pequation_atomic2067);
					constraint152=constraint();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, constraint152.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:344:4: lc= LPAREN pequation RPAREN
					{
					lc=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_pequation_atomic2074); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LPAREN.add(lc);

					pushFollow(FOLLOW_pequation_in_pequation_atomic2076);
					pequation153=pequation();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_pequation.add(pequation153.getTree());
					RPAREN154=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_pequation_atomic2078); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RPAREN.add(RPAREN154);

					// AST REWRITE
					// elements: pequation
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 344:31: -> ^( OP_PARENTHESIZED[$lc,\"(...)\"] pequation )
					{
						// ghidra/sleigh/grammar/SleighParser.g:344:34: ^( OP_PARENTHESIZED[$lc,\"(...)\"] pequation )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PARENTHESIZED, lc, "(...)"), root_1);
						adaptor.addChild(root_1, stream_pequation.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_atomic"


	public static class constraint_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "constraint"
	// ghidra/sleigh/grammar/SleighParser.g:347:1: constraint : identifier ( constraint_op ^ pexpression2 )? ;
	public final SleighParser.constraint_return constraint() throws RecognitionException {
		SleighParser.constraint_return retval = new SleighParser.constraint_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier155 =null;
		ParserRuleReturnScope constraint_op156 =null;
		ParserRuleReturnScope pexpression2157 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:348:2: ( identifier ( constraint_op ^ pexpression2 )? )
			// ghidra/sleigh/grammar/SleighParser.g:348:4: identifier ( constraint_op ^ pexpression2 )?
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_identifier_in_constraint2098);
			identifier155=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier155.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:348:15: ( constraint_op ^ pexpression2 )?
			int alt43=2;
			int LA43_0 = input.LA(1);
			if ( (LA43_0==ASSIGN||(LA43_0 >= GREAT && LA43_0 <= GREATEQUAL)||(LA43_0 >= LESS && LA43_0 <= LESSEQUAL)||LA43_0==NOTEQUAL) ) {
				alt43=1;
			}
			switch (alt43) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:348:16: constraint_op ^ pexpression2
					{
					pushFollow(FOLLOW_constraint_op_in_constraint2101);
					constraint_op156=constraint_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(constraint_op156.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_in_constraint2104);
					pexpression2157=pexpression2();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2157.getTree());

					}
					break;

			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "constraint"


	public static class constraint_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "constraint_op"
	// ghidra/sleigh/grammar/SleighParser.g:351:1: constraint_op : (lc= ASSIGN -> ^( OP_EQUAL[$lc] ) |lc= NOTEQUAL -> ^( OP_NOTEQUAL[$lc] ) |lc= LESS -> ^( OP_LESS[$lc] ) |lc= LESSEQUAL -> ^( OP_LESSEQUAL[$lc] ) |lc= GREAT -> ^( OP_GREAT[$lc] ) |lc= GREATEQUAL -> ^( OP_GREATEQUAL[$lc] ) );
	public final SleighParser.constraint_op_return constraint_op() throws RecognitionException {
		SleighParser.constraint_op_return retval = new SleighParser.constraint_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_NOTEQUAL=new RewriteRuleTokenStream(adaptor,"token NOTEQUAL");
		RewriteRuleTokenStream stream_LESSEQUAL=new RewriteRuleTokenStream(adaptor,"token LESSEQUAL");
		RewriteRuleTokenStream stream_GREAT=new RewriteRuleTokenStream(adaptor,"token GREAT");
		RewriteRuleTokenStream stream_LESS=new RewriteRuleTokenStream(adaptor,"token LESS");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleTokenStream stream_GREATEQUAL=new RewriteRuleTokenStream(adaptor,"token GREATEQUAL");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:352:2: (lc= ASSIGN -> ^( OP_EQUAL[$lc] ) |lc= NOTEQUAL -> ^( OP_NOTEQUAL[$lc] ) |lc= LESS -> ^( OP_LESS[$lc] ) |lc= LESSEQUAL -> ^( OP_LESSEQUAL[$lc] ) |lc= GREAT -> ^( OP_GREAT[$lc] ) |lc= GREATEQUAL -> ^( OP_GREATEQUAL[$lc] ) )
			int alt44=6;
			switch ( input.LA(1) ) {
			case ASSIGN:
				{
				alt44=1;
				}
				break;
			case NOTEQUAL:
				{
				alt44=2;
				}
				break;
			case LESS:
				{
				alt44=3;
				}
				break;
			case LESSEQUAL:
				{
				alt44=4;
				}
				break;
			case GREAT:
				{
				alt44=5;
				}
				break;
			case GREATEQUAL:
				{
				alt44=6;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 44, 0, input);
				throw nvae;
			}
			switch (alt44) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:352:4: lc= ASSIGN
					{
					lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_constraint_op2119); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_ASSIGN.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 352:14: -> ^( OP_EQUAL[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:352:17: ^( OP_EQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_EQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:353:4: lc= NOTEQUAL
					{
					lc=(Token)match(input,NOTEQUAL,FOLLOW_NOTEQUAL_in_constraint_op2133); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_NOTEQUAL.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 353:16: -> ^( OP_NOTEQUAL[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:353:19: ^( OP_NOTEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NOTEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:354:4: lc= LESS
					{
					lc=(Token)match(input,LESS,FOLLOW_LESS_in_constraint_op2147); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LESS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 354:12: -> ^( OP_LESS[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:354:15: ^( OP_LESS[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LESS, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighParser.g:355:4: lc= LESSEQUAL
					{
					lc=(Token)match(input,LESSEQUAL,FOLLOW_LESSEQUAL_in_constraint_op2161); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LESSEQUAL.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 355:17: -> ^( OP_LESSEQUAL[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:355:20: ^( OP_LESSEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LESSEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighParser.g:356:4: lc= GREAT
					{
					lc=(Token)match(input,GREAT,FOLLOW_GREAT_in_constraint_op2175); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_GREAT.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 356:13: -> ^( OP_GREAT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:356:16: ^( OP_GREAT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_GREAT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighParser.g:357:4: lc= GREATEQUAL
					{
					lc=(Token)match(input,GREATEQUAL,FOLLOW_GREATEQUAL_in_constraint_op2189); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_GREATEQUAL.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 357:18: -> ^( OP_GREATEQUAL[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:357:21: ^( OP_GREATEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_GREATEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "constraint_op"


	public static class pexpression_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression"
	// ghidra/sleigh/grammar/SleighParser.g:360:1: pexpression : pexpression_or ;
	public final SleighParser.pexpression_return pexpression() throws RecognitionException {
		SleighParser.pexpression_return retval = new SleighParser.pexpression_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_or158 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:361:2: ( pexpression_or )
			// ghidra/sleigh/grammar/SleighParser.g:361:4: pexpression_or
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_or_in_pexpression2207);
			pexpression_or158=pexpression_or();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_or158.getTree());

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression"


	public static class pexpression_or_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_or"
	// ghidra/sleigh/grammar/SleighParser.g:364:1: pexpression_or : pexpression_xor ( pexpression_or_op ^ pexpression_xor )* ;
	public final SleighParser.pexpression_or_return pexpression_or() throws RecognitionException {
		SleighParser.pexpression_or_return retval = new SleighParser.pexpression_or_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_xor159 =null;
		ParserRuleReturnScope pexpression_or_op160 =null;
		ParserRuleReturnScope pexpression_xor161 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:365:2: ( pexpression_xor ( pexpression_or_op ^ pexpression_xor )* )
			// ghidra/sleigh/grammar/SleighParser.g:365:4: pexpression_xor ( pexpression_or_op ^ pexpression_xor )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_xor_in_pexpression_or2218);
			pexpression_xor159=pexpression_xor();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_xor159.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:365:20: ( pexpression_or_op ^ pexpression_xor )*
			loop45:
			while (true) {
				int alt45=2;
				int LA45_0 = input.LA(1);
				if ( (LA45_0==PIPE||LA45_0==SPEC_OR) ) {
					alt45=1;
				}

				switch (alt45) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:365:21: pexpression_or_op ^ pexpression_xor
					{
					pushFollow(FOLLOW_pexpression_or_op_in_pexpression_or2221);
					pexpression_or_op160=pexpression_or_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_or_op160.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_xor_in_pexpression_or2224);
					pexpression_xor161=pexpression_xor();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_xor161.getTree());

					}
					break;

				default :
					break loop45;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_or"


	public static class pexpression_or_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_or_op"
	// ghidra/sleigh/grammar/SleighParser.g:368:1: pexpression_or_op : (lc= PIPE -> ^( OP_OR[$lc] ) |lc= SPEC_OR -> ^( OP_OR[$lc] ) );
	public final SleighParser.pexpression_or_op_return pexpression_or_op() throws RecognitionException {
		SleighParser.pexpression_or_op_return retval = new SleighParser.pexpression_or_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SPEC_OR=new RewriteRuleTokenStream(adaptor,"token SPEC_OR");
		RewriteRuleTokenStream stream_PIPE=new RewriteRuleTokenStream(adaptor,"token PIPE");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:369:2: (lc= PIPE -> ^( OP_OR[$lc] ) |lc= SPEC_OR -> ^( OP_OR[$lc] ) )
			int alt46=2;
			int LA46_0 = input.LA(1);
			if ( (LA46_0==PIPE) ) {
				alt46=1;
			}
			else if ( (LA46_0==SPEC_OR) ) {
				alt46=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 46, 0, input);
				throw nvae;
			}

			switch (alt46) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:369:4: lc= PIPE
					{
					lc=(Token)match(input,PIPE,FOLLOW_PIPE_in_pexpression_or_op2239); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_PIPE.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 369:12: -> ^( OP_OR[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:369:15: ^( OP_OR[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_OR, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:370:4: lc= SPEC_OR
					{
					lc=(Token)match(input,SPEC_OR,FOLLOW_SPEC_OR_in_pexpression_or_op2253); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_SPEC_OR.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 370:15: -> ^( OP_OR[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:370:18: ^( OP_OR[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_OR, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_or_op"


	public static class pexpression_xor_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_xor"
	// ghidra/sleigh/grammar/SleighParser.g:373:1: pexpression_xor : pexpression_and ( pexpression_xor_op ^ pexpression_and )* ;
	public final SleighParser.pexpression_xor_return pexpression_xor() throws RecognitionException {
		SleighParser.pexpression_xor_return retval = new SleighParser.pexpression_xor_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_and162 =null;
		ParserRuleReturnScope pexpression_xor_op163 =null;
		ParserRuleReturnScope pexpression_and164 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:374:2: ( pexpression_and ( pexpression_xor_op ^ pexpression_and )* )
			// ghidra/sleigh/grammar/SleighParser.g:374:4: pexpression_and ( pexpression_xor_op ^ pexpression_and )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_and_in_pexpression_xor2271);
			pexpression_and162=pexpression_and();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_and162.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:374:20: ( pexpression_xor_op ^ pexpression_and )*
			loop47:
			while (true) {
				int alt47=2;
				int LA47_0 = input.LA(1);
				if ( (LA47_0==CARET||LA47_0==SPEC_XOR) ) {
					alt47=1;
				}

				switch (alt47) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:374:21: pexpression_xor_op ^ pexpression_and
					{
					pushFollow(FOLLOW_pexpression_xor_op_in_pexpression_xor2274);
					pexpression_xor_op163=pexpression_xor_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_xor_op163.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_and_in_pexpression_xor2277);
					pexpression_and164=pexpression_and();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_and164.getTree());

					}
					break;

				default :
					break loop47;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_xor"


	public static class pexpression_xor_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_xor_op"
	// ghidra/sleigh/grammar/SleighParser.g:377:1: pexpression_xor_op : (lc= CARET -> ^( OP_XOR[$lc] ) |lc= SPEC_XOR -> ^( OP_XOR[$lc] ) );
	public final SleighParser.pexpression_xor_op_return pexpression_xor_op() throws RecognitionException {
		SleighParser.pexpression_xor_op_return retval = new SleighParser.pexpression_xor_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SPEC_XOR=new RewriteRuleTokenStream(adaptor,"token SPEC_XOR");
		RewriteRuleTokenStream stream_CARET=new RewriteRuleTokenStream(adaptor,"token CARET");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:378:2: (lc= CARET -> ^( OP_XOR[$lc] ) |lc= SPEC_XOR -> ^( OP_XOR[$lc] ) )
			int alt48=2;
			int LA48_0 = input.LA(1);
			if ( (LA48_0==CARET) ) {
				alt48=1;
			}
			else if ( (LA48_0==SPEC_XOR) ) {
				alt48=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 48, 0, input);
				throw nvae;
			}

			switch (alt48) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:378:4: lc= CARET
					{
					lc=(Token)match(input,CARET,FOLLOW_CARET_in_pexpression_xor_op2292); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_CARET.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 378:13: -> ^( OP_XOR[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:378:16: ^( OP_XOR[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_XOR, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:379:4: lc= SPEC_XOR
					{
					lc=(Token)match(input,SPEC_XOR,FOLLOW_SPEC_XOR_in_pexpression_xor_op2306); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_SPEC_XOR.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 379:16: -> ^( OP_XOR[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:379:19: ^( OP_XOR[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_XOR, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_xor_op"


	public static class pexpression_and_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_and"
	// ghidra/sleigh/grammar/SleighParser.g:382:1: pexpression_and : pexpression_shift ( pexpression_and_op ^ pexpression_shift )* ;
	public final SleighParser.pexpression_and_return pexpression_and() throws RecognitionException {
		SleighParser.pexpression_and_return retval = new SleighParser.pexpression_and_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_shift165 =null;
		ParserRuleReturnScope pexpression_and_op166 =null;
		ParserRuleReturnScope pexpression_shift167 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:383:2: ( pexpression_shift ( pexpression_and_op ^ pexpression_shift )* )
			// ghidra/sleigh/grammar/SleighParser.g:383:4: pexpression_shift ( pexpression_and_op ^ pexpression_shift )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_shift_in_pexpression_and2324);
			pexpression_shift165=pexpression_shift();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_shift165.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:383:22: ( pexpression_and_op ^ pexpression_shift )*
			loop49:
			while (true) {
				int alt49=2;
				int LA49_0 = input.LA(1);
				if ( (LA49_0==AMPERSAND||LA49_0==SPEC_AND) ) {
					alt49=1;
				}

				switch (alt49) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:383:23: pexpression_and_op ^ pexpression_shift
					{
					pushFollow(FOLLOW_pexpression_and_op_in_pexpression_and2327);
					pexpression_and_op166=pexpression_and_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_and_op166.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_shift_in_pexpression_and2330);
					pexpression_shift167=pexpression_shift();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_shift167.getTree());

					}
					break;

				default :
					break loop49;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_and"


	public static class pexpression_and_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_and_op"
	// ghidra/sleigh/grammar/SleighParser.g:386:1: pexpression_and_op : (lc= AMPERSAND -> ^( OP_AND[$lc] ) |lc= SPEC_AND -> ^( OP_AND[$lc] ) );
	public final SleighParser.pexpression_and_op_return pexpression_and_op() throws RecognitionException {
		SleighParser.pexpression_and_op_return retval = new SleighParser.pexpression_and_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_AMPERSAND=new RewriteRuleTokenStream(adaptor,"token AMPERSAND");
		RewriteRuleTokenStream stream_SPEC_AND=new RewriteRuleTokenStream(adaptor,"token SPEC_AND");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:387:2: (lc= AMPERSAND -> ^( OP_AND[$lc] ) |lc= SPEC_AND -> ^( OP_AND[$lc] ) )
			int alt50=2;
			int LA50_0 = input.LA(1);
			if ( (LA50_0==AMPERSAND) ) {
				alt50=1;
			}
			else if ( (LA50_0==SPEC_AND) ) {
				alt50=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 50, 0, input);
				throw nvae;
			}

			switch (alt50) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:387:4: lc= AMPERSAND
					{
					lc=(Token)match(input,AMPERSAND,FOLLOW_AMPERSAND_in_pexpression_and_op2345); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_AMPERSAND.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 387:17: -> ^( OP_AND[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:387:20: ^( OP_AND[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_AND, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:388:4: lc= SPEC_AND
					{
					lc=(Token)match(input,SPEC_AND,FOLLOW_SPEC_AND_in_pexpression_and_op2359); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_SPEC_AND.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 388:16: -> ^( OP_AND[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:388:19: ^( OP_AND[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_AND, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_and_op"


	public static class pexpression_shift_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_shift"
	// ghidra/sleigh/grammar/SleighParser.g:391:1: pexpression_shift : pexpression_add ( pexpression_shift_op ^ pexpression_add )* ;
	public final SleighParser.pexpression_shift_return pexpression_shift() throws RecognitionException {
		SleighParser.pexpression_shift_return retval = new SleighParser.pexpression_shift_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_add168 =null;
		ParserRuleReturnScope pexpression_shift_op169 =null;
		ParserRuleReturnScope pexpression_add170 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:392:2: ( pexpression_add ( pexpression_shift_op ^ pexpression_add )* )
			// ghidra/sleigh/grammar/SleighParser.g:392:4: pexpression_add ( pexpression_shift_op ^ pexpression_add )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_add_in_pexpression_shift2377);
			pexpression_add168=pexpression_add();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_add168.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:392:20: ( pexpression_shift_op ^ pexpression_add )*
			loop51:
			while (true) {
				int alt51=2;
				int LA51_0 = input.LA(1);
				if ( (LA51_0==LEFT||LA51_0==RIGHT) ) {
					alt51=1;
				}

				switch (alt51) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:392:21: pexpression_shift_op ^ pexpression_add
					{
					pushFollow(FOLLOW_pexpression_shift_op_in_pexpression_shift2380);
					pexpression_shift_op169=pexpression_shift_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_shift_op169.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_add_in_pexpression_shift2383);
					pexpression_add170=pexpression_add();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_add170.getTree());

					}
					break;

				default :
					break loop51;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_shift"


	public static class pexpression_shift_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_shift_op"
	// ghidra/sleigh/grammar/SleighParser.g:395:1: pexpression_shift_op : (lc= LEFT -> ^( OP_LEFT[$lc] ) |lc= RIGHT -> ^( OP_RIGHT[$lc] ) );
	public final SleighParser.pexpression_shift_op_return pexpression_shift_op() throws RecognitionException {
		SleighParser.pexpression_shift_op_return retval = new SleighParser.pexpression_shift_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_LEFT=new RewriteRuleTokenStream(adaptor,"token LEFT");
		RewriteRuleTokenStream stream_RIGHT=new RewriteRuleTokenStream(adaptor,"token RIGHT");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:396:2: (lc= LEFT -> ^( OP_LEFT[$lc] ) |lc= RIGHT -> ^( OP_RIGHT[$lc] ) )
			int alt52=2;
			int LA52_0 = input.LA(1);
			if ( (LA52_0==LEFT) ) {
				alt52=1;
			}
			else if ( (LA52_0==RIGHT) ) {
				alt52=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 52, 0, input);
				throw nvae;
			}

			switch (alt52) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:396:4: lc= LEFT
					{
					lc=(Token)match(input,LEFT,FOLLOW_LEFT_in_pexpression_shift_op2398); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LEFT.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 396:12: -> ^( OP_LEFT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:396:15: ^( OP_LEFT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LEFT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:397:4: lc= RIGHT
					{
					lc=(Token)match(input,RIGHT,FOLLOW_RIGHT_in_pexpression_shift_op2412); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RIGHT.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 397:13: -> ^( OP_RIGHT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:397:16: ^( OP_RIGHT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_RIGHT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_shift_op"


	public static class pexpression_add_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_add"
	// ghidra/sleigh/grammar/SleighParser.g:400:1: pexpression_add : pexpression_mult ( pexpression_add_op ^ pexpression_mult )* ;
	public final SleighParser.pexpression_add_return pexpression_add() throws RecognitionException {
		SleighParser.pexpression_add_return retval = new SleighParser.pexpression_add_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_mult171 =null;
		ParserRuleReturnScope pexpression_add_op172 =null;
		ParserRuleReturnScope pexpression_mult173 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:401:2: ( pexpression_mult ( pexpression_add_op ^ pexpression_mult )* )
			// ghidra/sleigh/grammar/SleighParser.g:401:4: pexpression_mult ( pexpression_add_op ^ pexpression_mult )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_mult_in_pexpression_add2430);
			pexpression_mult171=pexpression_mult();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_mult171.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:401:21: ( pexpression_add_op ^ pexpression_mult )*
			loop53:
			while (true) {
				int alt53=2;
				int LA53_0 = input.LA(1);
				if ( (LA53_0==MINUS||LA53_0==PLUS) ) {
					alt53=1;
				}

				switch (alt53) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:401:22: pexpression_add_op ^ pexpression_mult
					{
					pushFollow(FOLLOW_pexpression_add_op_in_pexpression_add2433);
					pexpression_add_op172=pexpression_add_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_add_op172.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_mult_in_pexpression_add2436);
					pexpression_mult173=pexpression_mult();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_mult173.getTree());

					}
					break;

				default :
					break loop53;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_add"


	public static class pexpression_add_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_add_op"
	// ghidra/sleigh/grammar/SleighParser.g:404:1: pexpression_add_op : (lc= PLUS -> ^( OP_ADD[$lc] ) |lc= MINUS -> ^( OP_SUB[$lc] ) );
	public final SleighParser.pexpression_add_op_return pexpression_add_op() throws RecognitionException {
		SleighParser.pexpression_add_op_return retval = new SleighParser.pexpression_add_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_PLUS=new RewriteRuleTokenStream(adaptor,"token PLUS");
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:405:2: (lc= PLUS -> ^( OP_ADD[$lc] ) |lc= MINUS -> ^( OP_SUB[$lc] ) )
			int alt54=2;
			int LA54_0 = input.LA(1);
			if ( (LA54_0==PLUS) ) {
				alt54=1;
			}
			else if ( (LA54_0==MINUS) ) {
				alt54=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 54, 0, input);
				throw nvae;
			}

			switch (alt54) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:405:4: lc= PLUS
					{
					lc=(Token)match(input,PLUS,FOLLOW_PLUS_in_pexpression_add_op2451); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_PLUS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 405:12: -> ^( OP_ADD[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:405:15: ^( OP_ADD[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ADD, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:406:4: lc= MINUS
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_pexpression_add_op2465); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_MINUS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 406:13: -> ^( OP_SUB[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:406:16: ^( OP_SUB[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SUB, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_add_op"


	public static class pexpression_mult_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_mult"
	// ghidra/sleigh/grammar/SleighParser.g:409:1: pexpression_mult : pexpression_unary ( pexpression_mult_op ^ pexpression_unary )* ;
	public final SleighParser.pexpression_mult_return pexpression_mult() throws RecognitionException {
		SleighParser.pexpression_mult_return retval = new SleighParser.pexpression_mult_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_unary174 =null;
		ParserRuleReturnScope pexpression_mult_op175 =null;
		ParserRuleReturnScope pexpression_unary176 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:410:2: ( pexpression_unary ( pexpression_mult_op ^ pexpression_unary )* )
			// ghidra/sleigh/grammar/SleighParser.g:410:4: pexpression_unary ( pexpression_mult_op ^ pexpression_unary )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_unary_in_pexpression_mult2483);
			pexpression_unary174=pexpression_unary();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_unary174.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:410:22: ( pexpression_mult_op ^ pexpression_unary )*
			loop55:
			while (true) {
				int alt55=2;
				int LA55_0 = input.LA(1);
				if ( (LA55_0==ASTERISK||LA55_0==SLASH) ) {
					alt55=1;
				}

				switch (alt55) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:410:23: pexpression_mult_op ^ pexpression_unary
					{
					pushFollow(FOLLOW_pexpression_mult_op_in_pexpression_mult2486);
					pexpression_mult_op175=pexpression_mult_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_mult_op175.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_unary_in_pexpression_mult2489);
					pexpression_unary176=pexpression_unary();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_unary176.getTree());

					}
					break;

				default :
					break loop55;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_mult"


	public static class pexpression_mult_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_mult_op"
	// ghidra/sleigh/grammar/SleighParser.g:413:1: pexpression_mult_op : (lc= ASTERISK -> ^( OP_MULT[$lc] ) |lc= SLASH -> ^( OP_DIV[$lc] ) );
	public final SleighParser.pexpression_mult_op_return pexpression_mult_op() throws RecognitionException {
		SleighParser.pexpression_mult_op_return retval = new SleighParser.pexpression_mult_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SLASH=new RewriteRuleTokenStream(adaptor,"token SLASH");
		RewriteRuleTokenStream stream_ASTERISK=new RewriteRuleTokenStream(adaptor,"token ASTERISK");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:414:2: (lc= ASTERISK -> ^( OP_MULT[$lc] ) |lc= SLASH -> ^( OP_DIV[$lc] ) )
			int alt56=2;
			int LA56_0 = input.LA(1);
			if ( (LA56_0==ASTERISK) ) {
				alt56=1;
			}
			else if ( (LA56_0==SLASH) ) {
				alt56=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 56, 0, input);
				throw nvae;
			}

			switch (alt56) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:414:4: lc= ASTERISK
					{
					lc=(Token)match(input,ASTERISK,FOLLOW_ASTERISK_in_pexpression_mult_op2504); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_ASTERISK.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 414:16: -> ^( OP_MULT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:414:19: ^( OP_MULT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_MULT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:415:4: lc= SLASH
					{
					lc=(Token)match(input,SLASH,FOLLOW_SLASH_in_pexpression_mult_op2518); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_SLASH.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 415:13: -> ^( OP_DIV[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:415:16: ^( OP_DIV[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DIV, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_mult_op"


	public static class pexpression_unary_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_unary"
	// ghidra/sleigh/grammar/SleighParser.g:418:1: pexpression_unary : ( pexpression_unary_op ^ pexpression_term | pexpression_func );
	public final SleighParser.pexpression_unary_return pexpression_unary() throws RecognitionException {
		SleighParser.pexpression_unary_return retval = new SleighParser.pexpression_unary_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_unary_op177 =null;
		ParserRuleReturnScope pexpression_term178 =null;
		ParserRuleReturnScope pexpression_func179 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:419:2: ( pexpression_unary_op ^ pexpression_term | pexpression_func )
			int alt57=2;
			int LA57_0 = input.LA(1);
			if ( (LA57_0==MINUS||LA57_0==TILDE) ) {
				alt57=1;
			}
			else if ( (LA57_0==BIN_INT||LA57_0==DEC_INT||(LA57_0 >= HEX_INT && LA57_0 <= KEY_WORDSIZE)||LA57_0==LPAREN) ) {
				alt57=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 57, 0, input);
				throw nvae;
			}

			switch (alt57) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:419:4: pexpression_unary_op ^ pexpression_term
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression_unary_op_in_pexpression_unary2536);
					pexpression_unary_op177=pexpression_unary_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_unary_op177.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_term_in_pexpression_unary2539);
					pexpression_term178=pexpression_term();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_term178.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:420:4: pexpression_func
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression_func_in_pexpression_unary2544);
					pexpression_func179=pexpression_func();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_func179.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_unary"


	public static class pexpression_unary_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_unary_op"
	// ghidra/sleigh/grammar/SleighParser.g:423:1: pexpression_unary_op : (lc= MINUS -> ^( OP_NEGATE[$lc] ) |lc= TILDE -> ^( OP_INVERT[$lc] ) );
	public final SleighParser.pexpression_unary_op_return pexpression_unary_op() throws RecognitionException {
		SleighParser.pexpression_unary_op_return retval = new SleighParser.pexpression_unary_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_TILDE=new RewriteRuleTokenStream(adaptor,"token TILDE");
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:424:2: (lc= MINUS -> ^( OP_NEGATE[$lc] ) |lc= TILDE -> ^( OP_INVERT[$lc] ) )
			int alt58=2;
			int LA58_0 = input.LA(1);
			if ( (LA58_0==MINUS) ) {
				alt58=1;
			}
			else if ( (LA58_0==TILDE) ) {
				alt58=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 58, 0, input);
				throw nvae;
			}

			switch (alt58) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:424:4: lc= MINUS
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_pexpression_unary_op2557); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_MINUS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 424:13: -> ^( OP_NEGATE[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:424:16: ^( OP_NEGATE[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NEGATE, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:425:4: lc= TILDE
					{
					lc=(Token)match(input,TILDE,FOLLOW_TILDE_in_pexpression_unary_op2571); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_TILDE.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 425:13: -> ^( OP_INVERT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:425:16: ^( OP_INVERT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_INVERT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_unary_op"


	public static class pexpression_func_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_func"
	// ghidra/sleigh/grammar/SleighParser.g:428:1: pexpression_func : ( pexpression_apply | pexpression_term );
	public final SleighParser.pexpression_func_return pexpression_func() throws RecognitionException {
		SleighParser.pexpression_func_return retval = new SleighParser.pexpression_func_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_apply180 =null;
		ParserRuleReturnScope pexpression_term181 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:429:2: ( pexpression_apply | pexpression_term )
			int alt59=2;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
				{
				int LA59_1 = input.LA(2);
				if ( (LA59_1==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_1==AMPERSAND||LA59_1==ASTERISK||LA59_1==CARET||LA59_1==COMMA||LA59_1==LEFT||LA59_1==MINUS||(LA59_1 >= PIPE && LA59_1 <= PLUS)||(LA59_1 >= RIGHT && LA59_1 <= RPAREN)||LA59_1==SEMI||LA59_1==SLASH||(LA59_1 >= SPEC_AND && LA59_1 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ALIGNMENT:
				{
				int LA59_2 = input.LA(2);
				if ( (LA59_2==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_2==AMPERSAND||LA59_2==ASTERISK||LA59_2==CARET||LA59_2==COMMA||LA59_2==LEFT||LA59_2==MINUS||(LA59_2 >= PIPE && LA59_2 <= PLUS)||(LA59_2 >= RIGHT && LA59_2 <= RPAREN)||LA59_2==SEMI||LA59_2==SLASH||(LA59_2 >= SPEC_AND && LA59_2 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA59_3 = input.LA(2);
				if ( (LA59_3==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_3==AMPERSAND||LA59_3==ASTERISK||LA59_3==CARET||LA59_3==COMMA||LA59_3==LEFT||LA59_3==MINUS||(LA59_3 >= PIPE && LA59_3 <= PLUS)||(LA59_3 >= RIGHT && LA59_3 <= RPAREN)||LA59_3==SEMI||LA59_3==SLASH||(LA59_3 >= SPEC_AND && LA59_3 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BIG:
				{
				int LA59_4 = input.LA(2);
				if ( (LA59_4==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_4==AMPERSAND||LA59_4==ASTERISK||LA59_4==CARET||LA59_4==COMMA||LA59_4==LEFT||LA59_4==MINUS||(LA59_4 >= PIPE && LA59_4 <= PLUS)||(LA59_4 >= RIGHT && LA59_4 <= RPAREN)||LA59_4==SEMI||LA59_4==SLASH||(LA59_4 >= SPEC_AND && LA59_4 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 4, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BITRANGE:
				{
				int LA59_5 = input.LA(2);
				if ( (LA59_5==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_5==AMPERSAND||LA59_5==ASTERISK||LA59_5==CARET||LA59_5==COMMA||LA59_5==LEFT||LA59_5==MINUS||(LA59_5 >= PIPE && LA59_5 <= PLUS)||(LA59_5 >= RIGHT && LA59_5 <= RPAREN)||LA59_5==SEMI||LA59_5==SLASH||(LA59_5 >= SPEC_AND && LA59_5 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 5, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BUILD:
				{
				int LA59_6 = input.LA(2);
				if ( (LA59_6==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_6==AMPERSAND||LA59_6==ASTERISK||LA59_6==CARET||LA59_6==COMMA||LA59_6==LEFT||LA59_6==MINUS||(LA59_6 >= PIPE && LA59_6 <= PLUS)||(LA59_6 >= RIGHT && LA59_6 <= RPAREN)||LA59_6==SEMI||LA59_6==SLASH||(LA59_6 >= SPEC_AND && LA59_6 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 6, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CALL:
				{
				int LA59_7 = input.LA(2);
				if ( (LA59_7==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_7==AMPERSAND||LA59_7==ASTERISK||LA59_7==CARET||LA59_7==COMMA||LA59_7==LEFT||LA59_7==MINUS||(LA59_7 >= PIPE && LA59_7 <= PLUS)||(LA59_7 >= RIGHT && LA59_7 <= RPAREN)||LA59_7==SEMI||LA59_7==SLASH||(LA59_7 >= SPEC_AND && LA59_7 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 7, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CONTEXT:
				{
				int LA59_8 = input.LA(2);
				if ( (LA59_8==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_8==AMPERSAND||LA59_8==ASTERISK||LA59_8==CARET||LA59_8==COMMA||LA59_8==LEFT||LA59_8==MINUS||(LA59_8 >= PIPE && LA59_8 <= PLUS)||(LA59_8 >= RIGHT && LA59_8 <= RPAREN)||LA59_8==SEMI||LA59_8==SLASH||(LA59_8 >= SPEC_AND && LA59_8 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 8, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CROSSBUILD:
				{
				int LA59_9 = input.LA(2);
				if ( (LA59_9==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_9==AMPERSAND||LA59_9==ASTERISK||LA59_9==CARET||LA59_9==COMMA||LA59_9==LEFT||LA59_9==MINUS||(LA59_9 >= PIPE && LA59_9 <= PLUS)||(LA59_9 >= RIGHT && LA59_9 <= RPAREN)||LA59_9==SEMI||LA59_9==SLASH||(LA59_9 >= SPEC_AND && LA59_9 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 9, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEC:
				{
				int LA59_10 = input.LA(2);
				if ( (LA59_10==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_10==AMPERSAND||LA59_10==ASTERISK||LA59_10==CARET||LA59_10==COMMA||LA59_10==LEFT||LA59_10==MINUS||(LA59_10 >= PIPE && LA59_10 <= PLUS)||(LA59_10 >= RIGHT && LA59_10 <= RPAREN)||LA59_10==SEMI||LA59_10==SLASH||(LA59_10 >= SPEC_AND && LA59_10 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 10, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFAULT:
				{
				int LA59_11 = input.LA(2);
				if ( (LA59_11==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_11==AMPERSAND||LA59_11==ASTERISK||LA59_11==CARET||LA59_11==COMMA||LA59_11==LEFT||LA59_11==MINUS||(LA59_11 >= PIPE && LA59_11 <= PLUS)||(LA59_11 >= RIGHT && LA59_11 <= RPAREN)||LA59_11==SEMI||LA59_11==SLASH||(LA59_11 >= SPEC_AND && LA59_11 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 11, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFINE:
				{
				int LA59_12 = input.LA(2);
				if ( (LA59_12==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_12==AMPERSAND||LA59_12==ASTERISK||LA59_12==CARET||LA59_12==COMMA||LA59_12==LEFT||LA59_12==MINUS||(LA59_12 >= PIPE && LA59_12 <= PLUS)||(LA59_12 >= RIGHT && LA59_12 <= RPAREN)||LA59_12==SEMI||LA59_12==SLASH||(LA59_12 >= SPEC_AND && LA59_12 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 12, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ENDIAN:
				{
				int LA59_13 = input.LA(2);
				if ( (LA59_13==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_13==AMPERSAND||LA59_13==ASTERISK||LA59_13==CARET||LA59_13==COMMA||LA59_13==LEFT||LA59_13==MINUS||(LA59_13 >= PIPE && LA59_13 <= PLUS)||(LA59_13 >= RIGHT && LA59_13 <= RPAREN)||LA59_13==SEMI||LA59_13==SLASH||(LA59_13 >= SPEC_AND && LA59_13 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 13, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_EXPORT:
				{
				int LA59_14 = input.LA(2);
				if ( (LA59_14==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_14==AMPERSAND||LA59_14==ASTERISK||LA59_14==CARET||LA59_14==COMMA||LA59_14==LEFT||LA59_14==MINUS||(LA59_14 >= PIPE && LA59_14 <= PLUS)||(LA59_14 >= RIGHT && LA59_14 <= RPAREN)||LA59_14==SEMI||LA59_14==SLASH||(LA59_14 >= SPEC_AND && LA59_14 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 14, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_GOTO:
				{
				int LA59_15 = input.LA(2);
				if ( (LA59_15==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_15==AMPERSAND||LA59_15==ASTERISK||LA59_15==CARET||LA59_15==COMMA||LA59_15==LEFT||LA59_15==MINUS||(LA59_15 >= PIPE && LA59_15 <= PLUS)||(LA59_15 >= RIGHT && LA59_15 <= RPAREN)||LA59_15==SEMI||LA59_15==SLASH||(LA59_15 >= SPEC_AND && LA59_15 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 15, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_HEX:
				{
				int LA59_16 = input.LA(2);
				if ( (LA59_16==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_16==AMPERSAND||LA59_16==ASTERISK||LA59_16==CARET||LA59_16==COMMA||LA59_16==LEFT||LA59_16==MINUS||(LA59_16 >= PIPE && LA59_16 <= PLUS)||(LA59_16 >= RIGHT && LA59_16 <= RPAREN)||LA59_16==SEMI||LA59_16==SLASH||(LA59_16 >= SPEC_AND && LA59_16 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 16, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LITTLE:
				{
				int LA59_17 = input.LA(2);
				if ( (LA59_17==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_17==AMPERSAND||LA59_17==ASTERISK||LA59_17==CARET||LA59_17==COMMA||LA59_17==LEFT||LA59_17==MINUS||(LA59_17 >= PIPE && LA59_17 <= PLUS)||(LA59_17 >= RIGHT && LA59_17 <= RPAREN)||LA59_17==SEMI||LA59_17==SLASH||(LA59_17 >= SPEC_AND && LA59_17 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 17, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LOCAL:
				{
				int LA59_18 = input.LA(2);
				if ( (LA59_18==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_18==AMPERSAND||LA59_18==ASTERISK||LA59_18==CARET||LA59_18==COMMA||LA59_18==LEFT||LA59_18==MINUS||(LA59_18 >= PIPE && LA59_18 <= PLUS)||(LA59_18 >= RIGHT && LA59_18 <= RPAREN)||LA59_18==SEMI||LA59_18==SLASH||(LA59_18 >= SPEC_AND && LA59_18 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 18, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_MACRO:
				{
				int LA59_19 = input.LA(2);
				if ( (LA59_19==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_19==AMPERSAND||LA59_19==ASTERISK||LA59_19==CARET||LA59_19==COMMA||LA59_19==LEFT||LA59_19==MINUS||(LA59_19 >= PIPE && LA59_19 <= PLUS)||(LA59_19 >= RIGHT && LA59_19 <= RPAREN)||LA59_19==SEMI||LA59_19==SLASH||(LA59_19 >= SPEC_AND && LA59_19 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 19, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NAMES:
				{
				int LA59_20 = input.LA(2);
				if ( (LA59_20==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_20==AMPERSAND||LA59_20==ASTERISK||LA59_20==CARET||LA59_20==COMMA||LA59_20==LEFT||LA59_20==MINUS||(LA59_20 >= PIPE && LA59_20 <= PLUS)||(LA59_20 >= RIGHT && LA59_20 <= RPAREN)||LA59_20==SEMI||LA59_20==SLASH||(LA59_20 >= SPEC_AND && LA59_20 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 20, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA59_21 = input.LA(2);
				if ( (LA59_21==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_21==AMPERSAND||LA59_21==ASTERISK||LA59_21==CARET||LA59_21==COMMA||LA59_21==LEFT||LA59_21==MINUS||(LA59_21 >= PIPE && LA59_21 <= PLUS)||(LA59_21 >= RIGHT && LA59_21 <= RPAREN)||LA59_21==SEMI||LA59_21==SLASH||(LA59_21 >= SPEC_AND && LA59_21 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 21, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_OFFSET:
				{
				int LA59_22 = input.LA(2);
				if ( (LA59_22==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_22==AMPERSAND||LA59_22==ASTERISK||LA59_22==CARET||LA59_22==COMMA||LA59_22==LEFT||LA59_22==MINUS||(LA59_22 >= PIPE && LA59_22 <= PLUS)||(LA59_22 >= RIGHT && LA59_22 <= RPAREN)||LA59_22==SEMI||LA59_22==SLASH||(LA59_22 >= SPEC_AND && LA59_22 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 22, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_PCODEOP:
				{
				int LA59_23 = input.LA(2);
				if ( (LA59_23==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_23==AMPERSAND||LA59_23==ASTERISK||LA59_23==CARET||LA59_23==COMMA||LA59_23==LEFT||LA59_23==MINUS||(LA59_23 >= PIPE && LA59_23 <= PLUS)||(LA59_23 >= RIGHT && LA59_23 <= RPAREN)||LA59_23==SEMI||LA59_23==SLASH||(LA59_23 >= SPEC_AND && LA59_23 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 23, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_RETURN:
				{
				int LA59_24 = input.LA(2);
				if ( (LA59_24==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_24==AMPERSAND||LA59_24==ASTERISK||LA59_24==CARET||LA59_24==COMMA||LA59_24==LEFT||LA59_24==MINUS||(LA59_24 >= PIPE && LA59_24 <= PLUS)||(LA59_24 >= RIGHT && LA59_24 <= RPAREN)||LA59_24==SEMI||LA59_24==SLASH||(LA59_24 >= SPEC_AND && LA59_24 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 24, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIGNED:
				{
				int LA59_25 = input.LA(2);
				if ( (LA59_25==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_25==AMPERSAND||LA59_25==ASTERISK||LA59_25==CARET||LA59_25==COMMA||LA59_25==LEFT||LA59_25==MINUS||(LA59_25 >= PIPE && LA59_25 <= PLUS)||(LA59_25 >= RIGHT && LA59_25 <= RPAREN)||LA59_25==SEMI||LA59_25==SLASH||(LA59_25 >= SPEC_AND && LA59_25 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 25, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIZE:
				{
				int LA59_26 = input.LA(2);
				if ( (LA59_26==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_26==AMPERSAND||LA59_26==ASTERISK||LA59_26==CARET||LA59_26==COMMA||LA59_26==LEFT||LA59_26==MINUS||(LA59_26 >= PIPE && LA59_26 <= PLUS)||(LA59_26 >= RIGHT && LA59_26 <= RPAREN)||LA59_26==SEMI||LA59_26==SLASH||(LA59_26 >= SPEC_AND && LA59_26 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 26, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SPACE:
				{
				int LA59_27 = input.LA(2);
				if ( (LA59_27==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_27==AMPERSAND||LA59_27==ASTERISK||LA59_27==CARET||LA59_27==COMMA||LA59_27==LEFT||LA59_27==MINUS||(LA59_27 >= PIPE && LA59_27 <= PLUS)||(LA59_27 >= RIGHT && LA59_27 <= RPAREN)||LA59_27==SEMI||LA59_27==SLASH||(LA59_27 >= SPEC_AND && LA59_27 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 27, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TOKEN:
				{
				int LA59_28 = input.LA(2);
				if ( (LA59_28==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_28==AMPERSAND||LA59_28==ASTERISK||LA59_28==CARET||LA59_28==COMMA||LA59_28==LEFT||LA59_28==MINUS||(LA59_28 >= PIPE && LA59_28 <= PLUS)||(LA59_28 >= RIGHT && LA59_28 <= RPAREN)||LA59_28==SEMI||LA59_28==SLASH||(LA59_28 >= SPEC_AND && LA59_28 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 28, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TYPE:
				{
				int LA59_29 = input.LA(2);
				if ( (LA59_29==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_29==AMPERSAND||LA59_29==ASTERISK||LA59_29==CARET||LA59_29==COMMA||LA59_29==LEFT||LA59_29==MINUS||(LA59_29 >= PIPE && LA59_29 <= PLUS)||(LA59_29 >= RIGHT && LA59_29 <= RPAREN)||LA59_29==SEMI||LA59_29==SLASH||(LA59_29 >= SPEC_AND && LA59_29 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 29, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_UNIMPL:
				{
				int LA59_30 = input.LA(2);
				if ( (LA59_30==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_30==AMPERSAND||LA59_30==ASTERISK||LA59_30==CARET||LA59_30==COMMA||LA59_30==LEFT||LA59_30==MINUS||(LA59_30 >= PIPE && LA59_30 <= PLUS)||(LA59_30 >= RIGHT && LA59_30 <= RPAREN)||LA59_30==SEMI||LA59_30==SLASH||(LA59_30 >= SPEC_AND && LA59_30 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 30, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VALUES:
				{
				int LA59_31 = input.LA(2);
				if ( (LA59_31==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_31==AMPERSAND||LA59_31==ASTERISK||LA59_31==CARET||LA59_31==COMMA||LA59_31==LEFT||LA59_31==MINUS||(LA59_31 >= PIPE && LA59_31 <= PLUS)||(LA59_31 >= RIGHT && LA59_31 <= RPAREN)||LA59_31==SEMI||LA59_31==SLASH||(LA59_31 >= SPEC_AND && LA59_31 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 31, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VARIABLES:
				{
				int LA59_32 = input.LA(2);
				if ( (LA59_32==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_32==AMPERSAND||LA59_32==ASTERISK||LA59_32==CARET||LA59_32==COMMA||LA59_32==LEFT||LA59_32==MINUS||(LA59_32 >= PIPE && LA59_32 <= PLUS)||(LA59_32 >= RIGHT && LA59_32 <= RPAREN)||LA59_32==SEMI||LA59_32==SLASH||(LA59_32 >= SPEC_AND && LA59_32 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 32, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_WORDSIZE:
				{
				int LA59_33 = input.LA(2);
				if ( (LA59_33==LPAREN) ) {
					alt59=1;
				}
				else if ( (LA59_33==AMPERSAND||LA59_33==ASTERISK||LA59_33==CARET||LA59_33==COMMA||LA59_33==LEFT||LA59_33==MINUS||(LA59_33 >= PIPE && LA59_33 <= PLUS)||(LA59_33 >= RIGHT && LA59_33 <= RPAREN)||LA59_33==SEMI||LA59_33==SLASH||(LA59_33 >= SPEC_AND && LA59_33 <= SPEC_XOR)) ) {
					alt59=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 59, 33, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case BIN_INT:
			case DEC_INT:
			case HEX_INT:
			case LPAREN:
				{
				alt59=2;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 59, 0, input);
				throw nvae;
			}
			switch (alt59) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:429:4: pexpression_apply
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression_apply_in_pexpression_func2589);
					pexpression_apply180=pexpression_apply();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_apply180.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:430:4: pexpression_term
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression_term_in_pexpression_func2594);
					pexpression_term181=pexpression_term();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_term181.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_func"


	public static class pexpression_apply_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_apply"
	// ghidra/sleigh/grammar/SleighParser.g:433:1: pexpression_apply : identifier pexpression_operands -> ^( OP_APPLY identifier ( pexpression_operands )? ) ;
	public final SleighParser.pexpression_apply_return pexpression_apply() throws RecognitionException {
		SleighParser.pexpression_apply_return retval = new SleighParser.pexpression_apply_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier182 =null;
		ParserRuleReturnScope pexpression_operands183 =null;

		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_pexpression_operands=new RewriteRuleSubtreeStream(adaptor,"rule pexpression_operands");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:434:2: ( identifier pexpression_operands -> ^( OP_APPLY identifier ( pexpression_operands )? ) )
			// ghidra/sleigh/grammar/SleighParser.g:434:4: identifier pexpression_operands
			{
			pushFollow(FOLLOW_identifier_in_pexpression_apply2605);
			identifier182=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier182.getTree());
			pushFollow(FOLLOW_pexpression_operands_in_pexpression_apply2607);
			pexpression_operands183=pexpression_operands();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_pexpression_operands.add(pexpression_operands183.getTree());
			// AST REWRITE
			// elements: pexpression_operands, identifier
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 434:36: -> ^( OP_APPLY identifier ( pexpression_operands )? )
			{
				// ghidra/sleigh/grammar/SleighParser.g:434:39: ^( OP_APPLY identifier ( pexpression_operands )? )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_APPLY, "OP_APPLY"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				// ghidra/sleigh/grammar/SleighParser.g:434:61: ( pexpression_operands )?
				if ( stream_pexpression_operands.hasNext() ) {
					adaptor.addChild(root_1, stream_pexpression_operands.nextTree());
				}
				stream_pexpression_operands.reset();

				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_apply"


	public static class pexpression_operands_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_operands"
	// ghidra/sleigh/grammar/SleighParser.g:437:1: pexpression_operands : LPAREN ! ( pexpression ( COMMA ! pexpression )* )? RPAREN !;
	public final SleighParser.pexpression_operands_return pexpression_operands() throws RecognitionException {
		SleighParser.pexpression_operands_return retval = new SleighParser.pexpression_operands_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LPAREN184=null;
		Token COMMA186=null;
		Token RPAREN188=null;
		ParserRuleReturnScope pexpression185 =null;
		ParserRuleReturnScope pexpression187 =null;

		CommonTree LPAREN184_tree=null;
		CommonTree COMMA186_tree=null;
		CommonTree RPAREN188_tree=null;

		try {
			// ghidra/sleigh/grammar/SleighParser.g:438:2: ( LPAREN ! ( pexpression ( COMMA ! pexpression )* )? RPAREN !)
			// ghidra/sleigh/grammar/SleighParser.g:438:4: LPAREN ! ( pexpression ( COMMA ! pexpression )* )? RPAREN !
			{
			root_0 = (CommonTree)adaptor.nil();


			LPAREN184=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_pexpression_operands2629); if (state.failed) return retval;
			// ghidra/sleigh/grammar/SleighParser.g:438:12: ( pexpression ( COMMA ! pexpression )* )?
			int alt61=2;
			int LA61_0 = input.LA(1);
			if ( (LA61_0==BIN_INT||LA61_0==DEC_INT||(LA61_0 >= HEX_INT && LA61_0 <= KEY_WORDSIZE)||(LA61_0 >= LPAREN && LA61_0 <= MINUS)||LA61_0==TILDE) ) {
				alt61=1;
			}
			switch (alt61) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:438:13: pexpression ( COMMA ! pexpression )*
					{
					pushFollow(FOLLOW_pexpression_in_pexpression_operands2633);
					pexpression185=pexpression();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression185.getTree());

					// ghidra/sleigh/grammar/SleighParser.g:438:25: ( COMMA ! pexpression )*
					loop60:
					while (true) {
						int alt60=2;
						int LA60_0 = input.LA(1);
						if ( (LA60_0==COMMA) ) {
							alt60=1;
						}

						switch (alt60) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:438:26: COMMA ! pexpression
							{
							COMMA186=(Token)match(input,COMMA,FOLLOW_COMMA_in_pexpression_operands2636); if (state.failed) return retval;
							pushFollow(FOLLOW_pexpression_in_pexpression_operands2639);
							pexpression187=pexpression();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression187.getTree());

							}
							break;

						default :
							break loop60;
						}
					}

					}
					break;

			}

			RPAREN188=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_pexpression_operands2646); if (state.failed) return retval;
			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_operands"


	public static class pexpression_term_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_term"
	// ghidra/sleigh/grammar/SleighParser.g:441:1: pexpression_term : ( identifier | integer |lc= LPAREN pexpression RPAREN -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression ) );
	public final SleighParser.pexpression_term_return pexpression_term() throws RecognitionException {
		SleighParser.pexpression_term_return retval = new SleighParser.pexpression_term_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token RPAREN192=null;
		ParserRuleReturnScope identifier189 =null;
		ParserRuleReturnScope integer190 =null;
		ParserRuleReturnScope pexpression191 =null;

		CommonTree lc_tree=null;
		CommonTree RPAREN192_tree=null;
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleSubtreeStream stream_pexpression=new RewriteRuleSubtreeStream(adaptor,"rule pexpression");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:442:2: ( identifier | integer |lc= LPAREN pexpression RPAREN -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression ) )
			int alt62=3;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
			case KEY_ALIGNMENT:
			case KEY_ATTACH:
			case KEY_BIG:
			case KEY_BITRANGE:
			case KEY_BUILD:
			case KEY_CALL:
			case KEY_CONTEXT:
			case KEY_CROSSBUILD:
			case KEY_DEC:
			case KEY_DEFAULT:
			case KEY_DEFINE:
			case KEY_ENDIAN:
			case KEY_EXPORT:
			case KEY_GOTO:
			case KEY_HEX:
			case KEY_LITTLE:
			case KEY_LOCAL:
			case KEY_MACRO:
			case KEY_NAMES:
			case KEY_NOFLOW:
			case KEY_OFFSET:
			case KEY_PCODEOP:
			case KEY_RETURN:
			case KEY_SIGNED:
			case KEY_SIZE:
			case KEY_SPACE:
			case KEY_TOKEN:
			case KEY_TYPE:
			case KEY_UNIMPL:
			case KEY_VALUES:
			case KEY_VARIABLES:
			case KEY_WORDSIZE:
				{
				alt62=1;
				}
				break;
			case BIN_INT:
			case DEC_INT:
			case HEX_INT:
				{
				alt62=2;
				}
				break;
			case LPAREN:
				{
				alt62=3;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 62, 0, input);
				throw nvae;
			}
			switch (alt62) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:442:4: identifier
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_identifier_in_pexpression_term2658);
					identifier189=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier189.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:443:4: integer
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_integer_in_pexpression_term2663);
					integer190=integer();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, integer190.getTree());

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:444:4: lc= LPAREN pexpression RPAREN
					{
					lc=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_pexpression_term2670); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LPAREN.add(lc);

					pushFollow(FOLLOW_pexpression_in_pexpression_term2672);
					pexpression191=pexpression();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_pexpression.add(pexpression191.getTree());
					RPAREN192=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_pexpression_term2674); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RPAREN.add(RPAREN192);

					// AST REWRITE
					// elements: pexpression
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 444:33: -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression )
					{
						// ghidra/sleigh/grammar/SleighParser.g:444:36: ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PARENTHESIZED, lc, "(...)"), root_1);
						adaptor.addChild(root_1, stream_pexpression.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_term"


	public static class pexpression2_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2"
	// ghidra/sleigh/grammar/SleighParser.g:447:1: pexpression2 : pexpression2_or ;
	public final SleighParser.pexpression2_return pexpression2() throws RecognitionException {
		SleighParser.pexpression2_return retval = new SleighParser.pexpression2_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_or193 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:448:2: ( pexpression2_or )
			// ghidra/sleigh/grammar/SleighParser.g:448:4: pexpression2_or
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_or_in_pexpression22694);
			pexpression2_or193=pexpression2_or();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_or193.getTree());

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2"


	public static class pexpression2_or_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_or"
	// ghidra/sleigh/grammar/SleighParser.g:451:1: pexpression2_or : pexpression2_xor ( pexpression2_or_op ^ pexpression2_xor )* ;
	public final SleighParser.pexpression2_or_return pexpression2_or() throws RecognitionException {
		SleighParser.pexpression2_or_return retval = new SleighParser.pexpression2_or_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_xor194 =null;
		ParserRuleReturnScope pexpression2_or_op195 =null;
		ParserRuleReturnScope pexpression2_xor196 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:452:2: ( pexpression2_xor ( pexpression2_or_op ^ pexpression2_xor )* )
			// ghidra/sleigh/grammar/SleighParser.g:452:4: pexpression2_xor ( pexpression2_or_op ^ pexpression2_xor )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_xor_in_pexpression2_or2705);
			pexpression2_xor194=pexpression2_xor();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_xor194.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:452:21: ( pexpression2_or_op ^ pexpression2_xor )*
			loop63:
			while (true) {
				int alt63=2;
				int LA63_0 = input.LA(1);
				if ( (LA63_0==SPEC_OR) ) {
					alt63=1;
				}

				switch (alt63) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:452:22: pexpression2_or_op ^ pexpression2_xor
					{
					pushFollow(FOLLOW_pexpression2_or_op_in_pexpression2_or2708);
					pexpression2_or_op195=pexpression2_or_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_or_op195.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_xor_in_pexpression2_or2711);
					pexpression2_xor196=pexpression2_xor();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_xor196.getTree());

					}
					break;

				default :
					break loop63;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_or"


	public static class pexpression2_or_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_or_op"
	// ghidra/sleigh/grammar/SleighParser.g:455:1: pexpression2_or_op : lc= SPEC_OR -> ^( OP_OR[$lc] ) ;
	public final SleighParser.pexpression2_or_op_return pexpression2_or_op() throws RecognitionException {
		SleighParser.pexpression2_or_op_return retval = new SleighParser.pexpression2_or_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SPEC_OR=new RewriteRuleTokenStream(adaptor,"token SPEC_OR");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:456:2: (lc= SPEC_OR -> ^( OP_OR[$lc] ) )
			// ghidra/sleigh/grammar/SleighParser.g:456:4: lc= SPEC_OR
			{
			lc=(Token)match(input,SPEC_OR,FOLLOW_SPEC_OR_in_pexpression2_or_op2726); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_SPEC_OR.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 456:15: -> ^( OP_OR[$lc] )
			{
				// ghidra/sleigh/grammar/SleighParser.g:456:18: ^( OP_OR[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_OR, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_or_op"


	public static class pexpression2_xor_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_xor"
	// ghidra/sleigh/grammar/SleighParser.g:459:1: pexpression2_xor : pexpression2_and ( pexpression2_xor_op ^ pexpression2_and )* ;
	public final SleighParser.pexpression2_xor_return pexpression2_xor() throws RecognitionException {
		SleighParser.pexpression2_xor_return retval = new SleighParser.pexpression2_xor_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_and197 =null;
		ParserRuleReturnScope pexpression2_xor_op198 =null;
		ParserRuleReturnScope pexpression2_and199 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:460:2: ( pexpression2_and ( pexpression2_xor_op ^ pexpression2_and )* )
			// ghidra/sleigh/grammar/SleighParser.g:460:4: pexpression2_and ( pexpression2_xor_op ^ pexpression2_and )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_and_in_pexpression2_xor2744);
			pexpression2_and197=pexpression2_and();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_and197.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:460:21: ( pexpression2_xor_op ^ pexpression2_and )*
			loop64:
			while (true) {
				int alt64=2;
				int LA64_0 = input.LA(1);
				if ( (LA64_0==SPEC_XOR) ) {
					alt64=1;
				}

				switch (alt64) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:460:22: pexpression2_xor_op ^ pexpression2_and
					{
					pushFollow(FOLLOW_pexpression2_xor_op_in_pexpression2_xor2747);
					pexpression2_xor_op198=pexpression2_xor_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_xor_op198.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_and_in_pexpression2_xor2750);
					pexpression2_and199=pexpression2_and();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_and199.getTree());

					}
					break;

				default :
					break loop64;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_xor"


	public static class pexpression2_xor_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_xor_op"
	// ghidra/sleigh/grammar/SleighParser.g:463:1: pexpression2_xor_op : lc= SPEC_XOR -> ^( OP_XOR[$lc] ) ;
	public final SleighParser.pexpression2_xor_op_return pexpression2_xor_op() throws RecognitionException {
		SleighParser.pexpression2_xor_op_return retval = new SleighParser.pexpression2_xor_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SPEC_XOR=new RewriteRuleTokenStream(adaptor,"token SPEC_XOR");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:464:2: (lc= SPEC_XOR -> ^( OP_XOR[$lc] ) )
			// ghidra/sleigh/grammar/SleighParser.g:464:4: lc= SPEC_XOR
			{
			lc=(Token)match(input,SPEC_XOR,FOLLOW_SPEC_XOR_in_pexpression2_xor_op2765); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_SPEC_XOR.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 464:16: -> ^( OP_XOR[$lc] )
			{
				// ghidra/sleigh/grammar/SleighParser.g:464:19: ^( OP_XOR[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_XOR, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_xor_op"


	public static class pexpression2_and_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_and"
	// ghidra/sleigh/grammar/SleighParser.g:467:1: pexpression2_and : pexpression2_shift ( pexpression2_and_op ^ pexpression2_shift )* ;
	public final SleighParser.pexpression2_and_return pexpression2_and() throws RecognitionException {
		SleighParser.pexpression2_and_return retval = new SleighParser.pexpression2_and_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_shift200 =null;
		ParserRuleReturnScope pexpression2_and_op201 =null;
		ParserRuleReturnScope pexpression2_shift202 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:468:2: ( pexpression2_shift ( pexpression2_and_op ^ pexpression2_shift )* )
			// ghidra/sleigh/grammar/SleighParser.g:468:4: pexpression2_shift ( pexpression2_and_op ^ pexpression2_shift )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_shift_in_pexpression2_and2783);
			pexpression2_shift200=pexpression2_shift();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_shift200.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:468:23: ( pexpression2_and_op ^ pexpression2_shift )*
			loop65:
			while (true) {
				int alt65=2;
				int LA65_0 = input.LA(1);
				if ( (LA65_0==SPEC_AND) ) {
					alt65=1;
				}

				switch (alt65) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:468:24: pexpression2_and_op ^ pexpression2_shift
					{
					pushFollow(FOLLOW_pexpression2_and_op_in_pexpression2_and2786);
					pexpression2_and_op201=pexpression2_and_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_and_op201.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_shift_in_pexpression2_and2789);
					pexpression2_shift202=pexpression2_shift();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_shift202.getTree());

					}
					break;

				default :
					break loop65;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_and"


	public static class pexpression2_and_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_and_op"
	// ghidra/sleigh/grammar/SleighParser.g:471:1: pexpression2_and_op : lc= SPEC_AND -> ^( OP_AND[$lc] ) ;
	public final SleighParser.pexpression2_and_op_return pexpression2_and_op() throws RecognitionException {
		SleighParser.pexpression2_and_op_return retval = new SleighParser.pexpression2_and_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SPEC_AND=new RewriteRuleTokenStream(adaptor,"token SPEC_AND");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:472:2: (lc= SPEC_AND -> ^( OP_AND[$lc] ) )
			// ghidra/sleigh/grammar/SleighParser.g:472:4: lc= SPEC_AND
			{
			lc=(Token)match(input,SPEC_AND,FOLLOW_SPEC_AND_in_pexpression2_and_op2804); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_SPEC_AND.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 472:16: -> ^( OP_AND[$lc] )
			{
				// ghidra/sleigh/grammar/SleighParser.g:472:19: ^( OP_AND[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_AND, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_and_op"


	public static class pexpression2_shift_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_shift"
	// ghidra/sleigh/grammar/SleighParser.g:475:1: pexpression2_shift : pexpression2_add ( pexpression2_shift_op ^ pexpression2_add )* ;
	public final SleighParser.pexpression2_shift_return pexpression2_shift() throws RecognitionException {
		SleighParser.pexpression2_shift_return retval = new SleighParser.pexpression2_shift_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_add203 =null;
		ParserRuleReturnScope pexpression2_shift_op204 =null;
		ParserRuleReturnScope pexpression2_add205 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:476:2: ( pexpression2_add ( pexpression2_shift_op ^ pexpression2_add )* )
			// ghidra/sleigh/grammar/SleighParser.g:476:4: pexpression2_add ( pexpression2_shift_op ^ pexpression2_add )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_add_in_pexpression2_shift2822);
			pexpression2_add203=pexpression2_add();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_add203.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:476:21: ( pexpression2_shift_op ^ pexpression2_add )*
			loop66:
			while (true) {
				int alt66=2;
				int LA66_0 = input.LA(1);
				if ( (LA66_0==LEFT||LA66_0==RIGHT) ) {
					alt66=1;
				}

				switch (alt66) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:476:22: pexpression2_shift_op ^ pexpression2_add
					{
					pushFollow(FOLLOW_pexpression2_shift_op_in_pexpression2_shift2825);
					pexpression2_shift_op204=pexpression2_shift_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_shift_op204.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_add_in_pexpression2_shift2828);
					pexpression2_add205=pexpression2_add();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_add205.getTree());

					}
					break;

				default :
					break loop66;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_shift"


	public static class pexpression2_shift_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_shift_op"
	// ghidra/sleigh/grammar/SleighParser.g:479:1: pexpression2_shift_op : (lc= LEFT -> ^( OP_LEFT[$lc] ) |lc= RIGHT -> ^( OP_RIGHT[$lc] ) );
	public final SleighParser.pexpression2_shift_op_return pexpression2_shift_op() throws RecognitionException {
		SleighParser.pexpression2_shift_op_return retval = new SleighParser.pexpression2_shift_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_LEFT=new RewriteRuleTokenStream(adaptor,"token LEFT");
		RewriteRuleTokenStream stream_RIGHT=new RewriteRuleTokenStream(adaptor,"token RIGHT");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:480:2: (lc= LEFT -> ^( OP_LEFT[$lc] ) |lc= RIGHT -> ^( OP_RIGHT[$lc] ) )
			int alt67=2;
			int LA67_0 = input.LA(1);
			if ( (LA67_0==LEFT) ) {
				alt67=1;
			}
			else if ( (LA67_0==RIGHT) ) {
				alt67=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 67, 0, input);
				throw nvae;
			}

			switch (alt67) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:480:4: lc= LEFT
					{
					lc=(Token)match(input,LEFT,FOLLOW_LEFT_in_pexpression2_shift_op2843); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LEFT.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 480:12: -> ^( OP_LEFT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:480:15: ^( OP_LEFT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LEFT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:481:4: lc= RIGHT
					{
					lc=(Token)match(input,RIGHT,FOLLOW_RIGHT_in_pexpression2_shift_op2857); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RIGHT.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 481:13: -> ^( OP_RIGHT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:481:16: ^( OP_RIGHT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_RIGHT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_shift_op"


	public static class pexpression2_add_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_add"
	// ghidra/sleigh/grammar/SleighParser.g:484:1: pexpression2_add : pexpression2_mult ( pexpression2_add_op ^ pexpression2_mult )* ;
	public final SleighParser.pexpression2_add_return pexpression2_add() throws RecognitionException {
		SleighParser.pexpression2_add_return retval = new SleighParser.pexpression2_add_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_mult206 =null;
		ParserRuleReturnScope pexpression2_add_op207 =null;
		ParserRuleReturnScope pexpression2_mult208 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:485:2: ( pexpression2_mult ( pexpression2_add_op ^ pexpression2_mult )* )
			// ghidra/sleigh/grammar/SleighParser.g:485:4: pexpression2_mult ( pexpression2_add_op ^ pexpression2_mult )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_mult_in_pexpression2_add2875);
			pexpression2_mult206=pexpression2_mult();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_mult206.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:485:22: ( pexpression2_add_op ^ pexpression2_mult )*
			loop68:
			while (true) {
				int alt68=2;
				int LA68_0 = input.LA(1);
				if ( (LA68_0==MINUS||LA68_0==PLUS) ) {
					alt68=1;
				}

				switch (alt68) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:485:23: pexpression2_add_op ^ pexpression2_mult
					{
					pushFollow(FOLLOW_pexpression2_add_op_in_pexpression2_add2878);
					pexpression2_add_op207=pexpression2_add_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_add_op207.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_mult_in_pexpression2_add2881);
					pexpression2_mult208=pexpression2_mult();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_mult208.getTree());

					}
					break;

				default :
					break loop68;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_add"


	public static class pexpression2_add_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_add_op"
	// ghidra/sleigh/grammar/SleighParser.g:488:1: pexpression2_add_op : (lc= PLUS -> ^( OP_ADD[$lc] ) |lc= MINUS -> ^( OP_SUB[$lc] ) );
	public final SleighParser.pexpression2_add_op_return pexpression2_add_op() throws RecognitionException {
		SleighParser.pexpression2_add_op_return retval = new SleighParser.pexpression2_add_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_PLUS=new RewriteRuleTokenStream(adaptor,"token PLUS");
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:489:2: (lc= PLUS -> ^( OP_ADD[$lc] ) |lc= MINUS -> ^( OP_SUB[$lc] ) )
			int alt69=2;
			int LA69_0 = input.LA(1);
			if ( (LA69_0==PLUS) ) {
				alt69=1;
			}
			else if ( (LA69_0==MINUS) ) {
				alt69=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 69, 0, input);
				throw nvae;
			}

			switch (alt69) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:489:4: lc= PLUS
					{
					lc=(Token)match(input,PLUS,FOLLOW_PLUS_in_pexpression2_add_op2896); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_PLUS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 489:12: -> ^( OP_ADD[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:489:15: ^( OP_ADD[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ADD, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:490:4: lc= MINUS
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_pexpression2_add_op2910); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_MINUS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 490:13: -> ^( OP_SUB[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:490:16: ^( OP_SUB[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SUB, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_add_op"


	public static class pexpression2_mult_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_mult"
	// ghidra/sleigh/grammar/SleighParser.g:493:1: pexpression2_mult : pexpression2_unary ( pexpression2_mult_op ^ pexpression2_unary )* ;
	public final SleighParser.pexpression2_mult_return pexpression2_mult() throws RecognitionException {
		SleighParser.pexpression2_mult_return retval = new SleighParser.pexpression2_mult_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_unary209 =null;
		ParserRuleReturnScope pexpression2_mult_op210 =null;
		ParserRuleReturnScope pexpression2_unary211 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:494:2: ( pexpression2_unary ( pexpression2_mult_op ^ pexpression2_unary )* )
			// ghidra/sleigh/grammar/SleighParser.g:494:4: pexpression2_unary ( pexpression2_mult_op ^ pexpression2_unary )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_unary_in_pexpression2_mult2928);
			pexpression2_unary209=pexpression2_unary();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_unary209.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:494:23: ( pexpression2_mult_op ^ pexpression2_unary )*
			loop70:
			while (true) {
				int alt70=2;
				int LA70_0 = input.LA(1);
				if ( (LA70_0==ASTERISK||LA70_0==SLASH) ) {
					alt70=1;
				}

				switch (alt70) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:494:24: pexpression2_mult_op ^ pexpression2_unary
					{
					pushFollow(FOLLOW_pexpression2_mult_op_in_pexpression2_mult2931);
					pexpression2_mult_op210=pexpression2_mult_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_mult_op210.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_unary_in_pexpression2_mult2934);
					pexpression2_unary211=pexpression2_unary();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_unary211.getTree());

					}
					break;

				default :
					break loop70;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_mult"


	public static class pexpression2_mult_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_mult_op"
	// ghidra/sleigh/grammar/SleighParser.g:497:1: pexpression2_mult_op : (lc= ASTERISK -> ^( OP_MULT[$lc] ) |lc= SLASH -> ^( OP_DIV[$lc] ) );
	public final SleighParser.pexpression2_mult_op_return pexpression2_mult_op() throws RecognitionException {
		SleighParser.pexpression2_mult_op_return retval = new SleighParser.pexpression2_mult_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SLASH=new RewriteRuleTokenStream(adaptor,"token SLASH");
		RewriteRuleTokenStream stream_ASTERISK=new RewriteRuleTokenStream(adaptor,"token ASTERISK");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:498:2: (lc= ASTERISK -> ^( OP_MULT[$lc] ) |lc= SLASH -> ^( OP_DIV[$lc] ) )
			int alt71=2;
			int LA71_0 = input.LA(1);
			if ( (LA71_0==ASTERISK) ) {
				alt71=1;
			}
			else if ( (LA71_0==SLASH) ) {
				alt71=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 71, 0, input);
				throw nvae;
			}

			switch (alt71) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:498:4: lc= ASTERISK
					{
					lc=(Token)match(input,ASTERISK,FOLLOW_ASTERISK_in_pexpression2_mult_op2949); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_ASTERISK.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 498:16: -> ^( OP_MULT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:498:19: ^( OP_MULT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_MULT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:499:4: lc= SLASH
					{
					lc=(Token)match(input,SLASH,FOLLOW_SLASH_in_pexpression2_mult_op2963); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_SLASH.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 499:13: -> ^( OP_DIV[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:499:16: ^( OP_DIV[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DIV, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_mult_op"


	public static class pexpression2_unary_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_unary"
	// ghidra/sleigh/grammar/SleighParser.g:502:1: pexpression2_unary : ( pexpression2_unary_op ^ pexpression2_term | pexpression2_func );
	public final SleighParser.pexpression2_unary_return pexpression2_unary() throws RecognitionException {
		SleighParser.pexpression2_unary_return retval = new SleighParser.pexpression2_unary_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_unary_op212 =null;
		ParserRuleReturnScope pexpression2_term213 =null;
		ParserRuleReturnScope pexpression2_func214 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:503:2: ( pexpression2_unary_op ^ pexpression2_term | pexpression2_func )
			int alt72=2;
			int LA72_0 = input.LA(1);
			if ( (LA72_0==MINUS||LA72_0==TILDE) ) {
				alt72=1;
			}
			else if ( (LA72_0==BIN_INT||LA72_0==DEC_INT||(LA72_0 >= HEX_INT && LA72_0 <= KEY_WORDSIZE)||LA72_0==LPAREN) ) {
				alt72=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 72, 0, input);
				throw nvae;
			}

			switch (alt72) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:503:4: pexpression2_unary_op ^ pexpression2_term
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression2_unary_op_in_pexpression2_unary2981);
					pexpression2_unary_op212=pexpression2_unary_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_unary_op212.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_term_in_pexpression2_unary2984);
					pexpression2_term213=pexpression2_term();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_term213.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:504:4: pexpression2_func
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression2_func_in_pexpression2_unary2989);
					pexpression2_func214=pexpression2_func();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_func214.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_unary"


	public static class pexpression2_unary_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_unary_op"
	// ghidra/sleigh/grammar/SleighParser.g:507:1: pexpression2_unary_op : (lc= MINUS -> ^( OP_NEGATE[$lc] ) |lc= TILDE -> ^( OP_INVERT[$lc] ) );
	public final SleighParser.pexpression2_unary_op_return pexpression2_unary_op() throws RecognitionException {
		SleighParser.pexpression2_unary_op_return retval = new SleighParser.pexpression2_unary_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_TILDE=new RewriteRuleTokenStream(adaptor,"token TILDE");
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:508:2: (lc= MINUS -> ^( OP_NEGATE[$lc] ) |lc= TILDE -> ^( OP_INVERT[$lc] ) )
			int alt73=2;
			int LA73_0 = input.LA(1);
			if ( (LA73_0==MINUS) ) {
				alt73=1;
			}
			else if ( (LA73_0==TILDE) ) {
				alt73=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 73, 0, input);
				throw nvae;
			}

			switch (alt73) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:508:4: lc= MINUS
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_pexpression2_unary_op3002); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_MINUS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 508:13: -> ^( OP_NEGATE[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:508:16: ^( OP_NEGATE[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NEGATE, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:509:4: lc= TILDE
					{
					lc=(Token)match(input,TILDE,FOLLOW_TILDE_in_pexpression2_unary_op3016); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_TILDE.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 509:13: -> ^( OP_INVERT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:509:16: ^( OP_INVERT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_INVERT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_unary_op"


	public static class pexpression2_func_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_func"
	// ghidra/sleigh/grammar/SleighParser.g:512:1: pexpression2_func : ( pexpression2_apply | pexpression2_term );
	public final SleighParser.pexpression2_func_return pexpression2_func() throws RecognitionException {
		SleighParser.pexpression2_func_return retval = new SleighParser.pexpression2_func_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_apply215 =null;
		ParserRuleReturnScope pexpression2_term216 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:513:2: ( pexpression2_apply | pexpression2_term )
			int alt74=2;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
				{
				int LA74_1 = input.LA(2);
				if ( (LA74_1==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_1==AMPERSAND||LA74_1==ASTERISK||LA74_1==COMMA||LA74_1==ELLIPSIS||LA74_1==KEY_UNIMPL||(LA74_1 >= LBRACE && LA74_1 <= LEFT)||LA74_1==MINUS||(LA74_1 >= PIPE && LA74_1 <= PLUS)||(LA74_1 >= RIGHT && LA74_1 <= RPAREN)||LA74_1==SEMI||LA74_1==SLASH||(LA74_1 >= SPEC_AND && LA74_1 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ALIGNMENT:
				{
				int LA74_2 = input.LA(2);
				if ( (LA74_2==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_2==AMPERSAND||LA74_2==ASTERISK||LA74_2==COMMA||LA74_2==ELLIPSIS||LA74_2==KEY_UNIMPL||(LA74_2 >= LBRACE && LA74_2 <= LEFT)||LA74_2==MINUS||(LA74_2 >= PIPE && LA74_2 <= PLUS)||(LA74_2 >= RIGHT && LA74_2 <= RPAREN)||LA74_2==SEMI||LA74_2==SLASH||(LA74_2 >= SPEC_AND && LA74_2 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA74_3 = input.LA(2);
				if ( (LA74_3==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_3==AMPERSAND||LA74_3==ASTERISK||LA74_3==COMMA||LA74_3==ELLIPSIS||LA74_3==KEY_UNIMPL||(LA74_3 >= LBRACE && LA74_3 <= LEFT)||LA74_3==MINUS||(LA74_3 >= PIPE && LA74_3 <= PLUS)||(LA74_3 >= RIGHT && LA74_3 <= RPAREN)||LA74_3==SEMI||LA74_3==SLASH||(LA74_3 >= SPEC_AND && LA74_3 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BIG:
				{
				int LA74_4 = input.LA(2);
				if ( (LA74_4==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_4==AMPERSAND||LA74_4==ASTERISK||LA74_4==COMMA||LA74_4==ELLIPSIS||LA74_4==KEY_UNIMPL||(LA74_4 >= LBRACE && LA74_4 <= LEFT)||LA74_4==MINUS||(LA74_4 >= PIPE && LA74_4 <= PLUS)||(LA74_4 >= RIGHT && LA74_4 <= RPAREN)||LA74_4==SEMI||LA74_4==SLASH||(LA74_4 >= SPEC_AND && LA74_4 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 4, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BITRANGE:
				{
				int LA74_5 = input.LA(2);
				if ( (LA74_5==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_5==AMPERSAND||LA74_5==ASTERISK||LA74_5==COMMA||LA74_5==ELLIPSIS||LA74_5==KEY_UNIMPL||(LA74_5 >= LBRACE && LA74_5 <= LEFT)||LA74_5==MINUS||(LA74_5 >= PIPE && LA74_5 <= PLUS)||(LA74_5 >= RIGHT && LA74_5 <= RPAREN)||LA74_5==SEMI||LA74_5==SLASH||(LA74_5 >= SPEC_AND && LA74_5 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 5, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BUILD:
				{
				int LA74_6 = input.LA(2);
				if ( (LA74_6==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_6==AMPERSAND||LA74_6==ASTERISK||LA74_6==COMMA||LA74_6==ELLIPSIS||LA74_6==KEY_UNIMPL||(LA74_6 >= LBRACE && LA74_6 <= LEFT)||LA74_6==MINUS||(LA74_6 >= PIPE && LA74_6 <= PLUS)||(LA74_6 >= RIGHT && LA74_6 <= RPAREN)||LA74_6==SEMI||LA74_6==SLASH||(LA74_6 >= SPEC_AND && LA74_6 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 6, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CALL:
				{
				int LA74_7 = input.LA(2);
				if ( (LA74_7==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_7==AMPERSAND||LA74_7==ASTERISK||LA74_7==COMMA||LA74_7==ELLIPSIS||LA74_7==KEY_UNIMPL||(LA74_7 >= LBRACE && LA74_7 <= LEFT)||LA74_7==MINUS||(LA74_7 >= PIPE && LA74_7 <= PLUS)||(LA74_7 >= RIGHT && LA74_7 <= RPAREN)||LA74_7==SEMI||LA74_7==SLASH||(LA74_7 >= SPEC_AND && LA74_7 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 7, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CONTEXT:
				{
				int LA74_8 = input.LA(2);
				if ( (LA74_8==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_8==AMPERSAND||LA74_8==ASTERISK||LA74_8==COMMA||LA74_8==ELLIPSIS||LA74_8==KEY_UNIMPL||(LA74_8 >= LBRACE && LA74_8 <= LEFT)||LA74_8==MINUS||(LA74_8 >= PIPE && LA74_8 <= PLUS)||(LA74_8 >= RIGHT && LA74_8 <= RPAREN)||LA74_8==SEMI||LA74_8==SLASH||(LA74_8 >= SPEC_AND && LA74_8 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 8, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CROSSBUILD:
				{
				int LA74_9 = input.LA(2);
				if ( (LA74_9==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_9==AMPERSAND||LA74_9==ASTERISK||LA74_9==COMMA||LA74_9==ELLIPSIS||LA74_9==KEY_UNIMPL||(LA74_9 >= LBRACE && LA74_9 <= LEFT)||LA74_9==MINUS||(LA74_9 >= PIPE && LA74_9 <= PLUS)||(LA74_9 >= RIGHT && LA74_9 <= RPAREN)||LA74_9==SEMI||LA74_9==SLASH||(LA74_9 >= SPEC_AND && LA74_9 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 9, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEC:
				{
				int LA74_10 = input.LA(2);
				if ( (LA74_10==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_10==AMPERSAND||LA74_10==ASTERISK||LA74_10==COMMA||LA74_10==ELLIPSIS||LA74_10==KEY_UNIMPL||(LA74_10 >= LBRACE && LA74_10 <= LEFT)||LA74_10==MINUS||(LA74_10 >= PIPE && LA74_10 <= PLUS)||(LA74_10 >= RIGHT && LA74_10 <= RPAREN)||LA74_10==SEMI||LA74_10==SLASH||(LA74_10 >= SPEC_AND && LA74_10 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 10, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFAULT:
				{
				int LA74_11 = input.LA(2);
				if ( (LA74_11==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_11==AMPERSAND||LA74_11==ASTERISK||LA74_11==COMMA||LA74_11==ELLIPSIS||LA74_11==KEY_UNIMPL||(LA74_11 >= LBRACE && LA74_11 <= LEFT)||LA74_11==MINUS||(LA74_11 >= PIPE && LA74_11 <= PLUS)||(LA74_11 >= RIGHT && LA74_11 <= RPAREN)||LA74_11==SEMI||LA74_11==SLASH||(LA74_11 >= SPEC_AND && LA74_11 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 11, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFINE:
				{
				int LA74_12 = input.LA(2);
				if ( (LA74_12==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_12==AMPERSAND||LA74_12==ASTERISK||LA74_12==COMMA||LA74_12==ELLIPSIS||LA74_12==KEY_UNIMPL||(LA74_12 >= LBRACE && LA74_12 <= LEFT)||LA74_12==MINUS||(LA74_12 >= PIPE && LA74_12 <= PLUS)||(LA74_12 >= RIGHT && LA74_12 <= RPAREN)||LA74_12==SEMI||LA74_12==SLASH||(LA74_12 >= SPEC_AND && LA74_12 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 12, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ENDIAN:
				{
				int LA74_13 = input.LA(2);
				if ( (LA74_13==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_13==AMPERSAND||LA74_13==ASTERISK||LA74_13==COMMA||LA74_13==ELLIPSIS||LA74_13==KEY_UNIMPL||(LA74_13 >= LBRACE && LA74_13 <= LEFT)||LA74_13==MINUS||(LA74_13 >= PIPE && LA74_13 <= PLUS)||(LA74_13 >= RIGHT && LA74_13 <= RPAREN)||LA74_13==SEMI||LA74_13==SLASH||(LA74_13 >= SPEC_AND && LA74_13 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 13, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_EXPORT:
				{
				int LA74_14 = input.LA(2);
				if ( (LA74_14==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_14==AMPERSAND||LA74_14==ASTERISK||LA74_14==COMMA||LA74_14==ELLIPSIS||LA74_14==KEY_UNIMPL||(LA74_14 >= LBRACE && LA74_14 <= LEFT)||LA74_14==MINUS||(LA74_14 >= PIPE && LA74_14 <= PLUS)||(LA74_14 >= RIGHT && LA74_14 <= RPAREN)||LA74_14==SEMI||LA74_14==SLASH||(LA74_14 >= SPEC_AND && LA74_14 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 14, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_GOTO:
				{
				int LA74_15 = input.LA(2);
				if ( (LA74_15==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_15==AMPERSAND||LA74_15==ASTERISK||LA74_15==COMMA||LA74_15==ELLIPSIS||LA74_15==KEY_UNIMPL||(LA74_15 >= LBRACE && LA74_15 <= LEFT)||LA74_15==MINUS||(LA74_15 >= PIPE && LA74_15 <= PLUS)||(LA74_15 >= RIGHT && LA74_15 <= RPAREN)||LA74_15==SEMI||LA74_15==SLASH||(LA74_15 >= SPEC_AND && LA74_15 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 15, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_HEX:
				{
				int LA74_16 = input.LA(2);
				if ( (LA74_16==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_16==AMPERSAND||LA74_16==ASTERISK||LA74_16==COMMA||LA74_16==ELLIPSIS||LA74_16==KEY_UNIMPL||(LA74_16 >= LBRACE && LA74_16 <= LEFT)||LA74_16==MINUS||(LA74_16 >= PIPE && LA74_16 <= PLUS)||(LA74_16 >= RIGHT && LA74_16 <= RPAREN)||LA74_16==SEMI||LA74_16==SLASH||(LA74_16 >= SPEC_AND && LA74_16 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 16, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LITTLE:
				{
				int LA74_17 = input.LA(2);
				if ( (LA74_17==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_17==AMPERSAND||LA74_17==ASTERISK||LA74_17==COMMA||LA74_17==ELLIPSIS||LA74_17==KEY_UNIMPL||(LA74_17 >= LBRACE && LA74_17 <= LEFT)||LA74_17==MINUS||(LA74_17 >= PIPE && LA74_17 <= PLUS)||(LA74_17 >= RIGHT && LA74_17 <= RPAREN)||LA74_17==SEMI||LA74_17==SLASH||(LA74_17 >= SPEC_AND && LA74_17 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 17, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LOCAL:
				{
				int LA74_18 = input.LA(2);
				if ( (LA74_18==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_18==AMPERSAND||LA74_18==ASTERISK||LA74_18==COMMA||LA74_18==ELLIPSIS||LA74_18==KEY_UNIMPL||(LA74_18 >= LBRACE && LA74_18 <= LEFT)||LA74_18==MINUS||(LA74_18 >= PIPE && LA74_18 <= PLUS)||(LA74_18 >= RIGHT && LA74_18 <= RPAREN)||LA74_18==SEMI||LA74_18==SLASH||(LA74_18 >= SPEC_AND && LA74_18 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 18, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_MACRO:
				{
				int LA74_19 = input.LA(2);
				if ( (LA74_19==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_19==AMPERSAND||LA74_19==ASTERISK||LA74_19==COMMA||LA74_19==ELLIPSIS||LA74_19==KEY_UNIMPL||(LA74_19 >= LBRACE && LA74_19 <= LEFT)||LA74_19==MINUS||(LA74_19 >= PIPE && LA74_19 <= PLUS)||(LA74_19 >= RIGHT && LA74_19 <= RPAREN)||LA74_19==SEMI||LA74_19==SLASH||(LA74_19 >= SPEC_AND && LA74_19 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 19, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NAMES:
				{
				int LA74_20 = input.LA(2);
				if ( (LA74_20==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_20==AMPERSAND||LA74_20==ASTERISK||LA74_20==COMMA||LA74_20==ELLIPSIS||LA74_20==KEY_UNIMPL||(LA74_20 >= LBRACE && LA74_20 <= LEFT)||LA74_20==MINUS||(LA74_20 >= PIPE && LA74_20 <= PLUS)||(LA74_20 >= RIGHT && LA74_20 <= RPAREN)||LA74_20==SEMI||LA74_20==SLASH||(LA74_20 >= SPEC_AND && LA74_20 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 20, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA74_21 = input.LA(2);
				if ( (LA74_21==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_21==AMPERSAND||LA74_21==ASTERISK||LA74_21==COMMA||LA74_21==ELLIPSIS||LA74_21==KEY_UNIMPL||(LA74_21 >= LBRACE && LA74_21 <= LEFT)||LA74_21==MINUS||(LA74_21 >= PIPE && LA74_21 <= PLUS)||(LA74_21 >= RIGHT && LA74_21 <= RPAREN)||LA74_21==SEMI||LA74_21==SLASH||(LA74_21 >= SPEC_AND && LA74_21 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 21, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_OFFSET:
				{
				int LA74_22 = input.LA(2);
				if ( (LA74_22==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_22==AMPERSAND||LA74_22==ASTERISK||LA74_22==COMMA||LA74_22==ELLIPSIS||LA74_22==KEY_UNIMPL||(LA74_22 >= LBRACE && LA74_22 <= LEFT)||LA74_22==MINUS||(LA74_22 >= PIPE && LA74_22 <= PLUS)||(LA74_22 >= RIGHT && LA74_22 <= RPAREN)||LA74_22==SEMI||LA74_22==SLASH||(LA74_22 >= SPEC_AND && LA74_22 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 22, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_PCODEOP:
				{
				int LA74_23 = input.LA(2);
				if ( (LA74_23==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_23==AMPERSAND||LA74_23==ASTERISK||LA74_23==COMMA||LA74_23==ELLIPSIS||LA74_23==KEY_UNIMPL||(LA74_23 >= LBRACE && LA74_23 <= LEFT)||LA74_23==MINUS||(LA74_23 >= PIPE && LA74_23 <= PLUS)||(LA74_23 >= RIGHT && LA74_23 <= RPAREN)||LA74_23==SEMI||LA74_23==SLASH||(LA74_23 >= SPEC_AND && LA74_23 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 23, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_RETURN:
				{
				int LA74_24 = input.LA(2);
				if ( (LA74_24==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_24==AMPERSAND||LA74_24==ASTERISK||LA74_24==COMMA||LA74_24==ELLIPSIS||LA74_24==KEY_UNIMPL||(LA74_24 >= LBRACE && LA74_24 <= LEFT)||LA74_24==MINUS||(LA74_24 >= PIPE && LA74_24 <= PLUS)||(LA74_24 >= RIGHT && LA74_24 <= RPAREN)||LA74_24==SEMI||LA74_24==SLASH||(LA74_24 >= SPEC_AND && LA74_24 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 24, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIGNED:
				{
				int LA74_25 = input.LA(2);
				if ( (LA74_25==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_25==AMPERSAND||LA74_25==ASTERISK||LA74_25==COMMA||LA74_25==ELLIPSIS||LA74_25==KEY_UNIMPL||(LA74_25 >= LBRACE && LA74_25 <= LEFT)||LA74_25==MINUS||(LA74_25 >= PIPE && LA74_25 <= PLUS)||(LA74_25 >= RIGHT && LA74_25 <= RPAREN)||LA74_25==SEMI||LA74_25==SLASH||(LA74_25 >= SPEC_AND && LA74_25 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 25, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIZE:
				{
				int LA74_26 = input.LA(2);
				if ( (LA74_26==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_26==AMPERSAND||LA74_26==ASTERISK||LA74_26==COMMA||LA74_26==ELLIPSIS||LA74_26==KEY_UNIMPL||(LA74_26 >= LBRACE && LA74_26 <= LEFT)||LA74_26==MINUS||(LA74_26 >= PIPE && LA74_26 <= PLUS)||(LA74_26 >= RIGHT && LA74_26 <= RPAREN)||LA74_26==SEMI||LA74_26==SLASH||(LA74_26 >= SPEC_AND && LA74_26 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 26, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SPACE:
				{
				int LA74_27 = input.LA(2);
				if ( (LA74_27==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_27==AMPERSAND||LA74_27==ASTERISK||LA74_27==COMMA||LA74_27==ELLIPSIS||LA74_27==KEY_UNIMPL||(LA74_27 >= LBRACE && LA74_27 <= LEFT)||LA74_27==MINUS||(LA74_27 >= PIPE && LA74_27 <= PLUS)||(LA74_27 >= RIGHT && LA74_27 <= RPAREN)||LA74_27==SEMI||LA74_27==SLASH||(LA74_27 >= SPEC_AND && LA74_27 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 27, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TOKEN:
				{
				int LA74_28 = input.LA(2);
				if ( (LA74_28==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_28==AMPERSAND||LA74_28==ASTERISK||LA74_28==COMMA||LA74_28==ELLIPSIS||LA74_28==KEY_UNIMPL||(LA74_28 >= LBRACE && LA74_28 <= LEFT)||LA74_28==MINUS||(LA74_28 >= PIPE && LA74_28 <= PLUS)||(LA74_28 >= RIGHT && LA74_28 <= RPAREN)||LA74_28==SEMI||LA74_28==SLASH||(LA74_28 >= SPEC_AND && LA74_28 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 28, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TYPE:
				{
				int LA74_29 = input.LA(2);
				if ( (LA74_29==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_29==AMPERSAND||LA74_29==ASTERISK||LA74_29==COMMA||LA74_29==ELLIPSIS||LA74_29==KEY_UNIMPL||(LA74_29 >= LBRACE && LA74_29 <= LEFT)||LA74_29==MINUS||(LA74_29 >= PIPE && LA74_29 <= PLUS)||(LA74_29 >= RIGHT && LA74_29 <= RPAREN)||LA74_29==SEMI||LA74_29==SLASH||(LA74_29 >= SPEC_AND && LA74_29 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 29, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_UNIMPL:
				{
				int LA74_30 = input.LA(2);
				if ( (LA74_30==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_30==AMPERSAND||LA74_30==ASTERISK||LA74_30==COMMA||LA74_30==ELLIPSIS||LA74_30==KEY_UNIMPL||(LA74_30 >= LBRACE && LA74_30 <= LEFT)||LA74_30==MINUS||(LA74_30 >= PIPE && LA74_30 <= PLUS)||(LA74_30 >= RIGHT && LA74_30 <= RPAREN)||LA74_30==SEMI||LA74_30==SLASH||(LA74_30 >= SPEC_AND && LA74_30 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 30, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VALUES:
				{
				int LA74_31 = input.LA(2);
				if ( (LA74_31==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_31==AMPERSAND||LA74_31==ASTERISK||LA74_31==COMMA||LA74_31==ELLIPSIS||LA74_31==KEY_UNIMPL||(LA74_31 >= LBRACE && LA74_31 <= LEFT)||LA74_31==MINUS||(LA74_31 >= PIPE && LA74_31 <= PLUS)||(LA74_31 >= RIGHT && LA74_31 <= RPAREN)||LA74_31==SEMI||LA74_31==SLASH||(LA74_31 >= SPEC_AND && LA74_31 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 31, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VARIABLES:
				{
				int LA74_32 = input.LA(2);
				if ( (LA74_32==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_32==AMPERSAND||LA74_32==ASTERISK||LA74_32==COMMA||LA74_32==ELLIPSIS||LA74_32==KEY_UNIMPL||(LA74_32 >= LBRACE && LA74_32 <= LEFT)||LA74_32==MINUS||(LA74_32 >= PIPE && LA74_32 <= PLUS)||(LA74_32 >= RIGHT && LA74_32 <= RPAREN)||LA74_32==SEMI||LA74_32==SLASH||(LA74_32 >= SPEC_AND && LA74_32 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 32, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_WORDSIZE:
				{
				int LA74_33 = input.LA(2);
				if ( (LA74_33==LPAREN) ) {
					alt74=1;
				}
				else if ( (LA74_33==AMPERSAND||LA74_33==ASTERISK||LA74_33==COMMA||LA74_33==ELLIPSIS||LA74_33==KEY_UNIMPL||(LA74_33 >= LBRACE && LA74_33 <= LEFT)||LA74_33==MINUS||(LA74_33 >= PIPE && LA74_33 <= PLUS)||(LA74_33 >= RIGHT && LA74_33 <= RPAREN)||LA74_33==SEMI||LA74_33==SLASH||(LA74_33 >= SPEC_AND && LA74_33 <= SPEC_XOR)) ) {
					alt74=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 74, 33, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case BIN_INT:
			case DEC_INT:
			case HEX_INT:
			case LPAREN:
				{
				alt74=2;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 74, 0, input);
				throw nvae;
			}
			switch (alt74) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:513:4: pexpression2_apply
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression2_apply_in_pexpression2_func3034);
					pexpression2_apply215=pexpression2_apply();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_apply215.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:514:4: pexpression2_term
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression2_term_in_pexpression2_func3039);
					pexpression2_term216=pexpression2_term();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_term216.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_func"


	public static class pexpression2_apply_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_apply"
	// ghidra/sleigh/grammar/SleighParser.g:517:1: pexpression2_apply : identifier pexpression2_operands -> ^( OP_APPLY identifier ( pexpression2_operands )? ) ;
	public final SleighParser.pexpression2_apply_return pexpression2_apply() throws RecognitionException {
		SleighParser.pexpression2_apply_return retval = new SleighParser.pexpression2_apply_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier217 =null;
		ParserRuleReturnScope pexpression2_operands218 =null;

		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_pexpression2_operands=new RewriteRuleSubtreeStream(adaptor,"rule pexpression2_operands");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:518:2: ( identifier pexpression2_operands -> ^( OP_APPLY identifier ( pexpression2_operands )? ) )
			// ghidra/sleigh/grammar/SleighParser.g:518:4: identifier pexpression2_operands
			{
			pushFollow(FOLLOW_identifier_in_pexpression2_apply3050);
			identifier217=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier217.getTree());
			pushFollow(FOLLOW_pexpression2_operands_in_pexpression2_apply3052);
			pexpression2_operands218=pexpression2_operands();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_pexpression2_operands.add(pexpression2_operands218.getTree());
			// AST REWRITE
			// elements: identifier, pexpression2_operands
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 518:37: -> ^( OP_APPLY identifier ( pexpression2_operands )? )
			{
				// ghidra/sleigh/grammar/SleighParser.g:518:40: ^( OP_APPLY identifier ( pexpression2_operands )? )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_APPLY, "OP_APPLY"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				// ghidra/sleigh/grammar/SleighParser.g:518:62: ( pexpression2_operands )?
				if ( stream_pexpression2_operands.hasNext() ) {
					adaptor.addChild(root_1, stream_pexpression2_operands.nextTree());
				}
				stream_pexpression2_operands.reset();

				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_apply"


	public static class pexpression2_operands_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_operands"
	// ghidra/sleigh/grammar/SleighParser.g:521:1: pexpression2_operands : LPAREN ! ( pexpression2 ( COMMA ! pexpression2 )* )? RPAREN !;
	public final SleighParser.pexpression2_operands_return pexpression2_operands() throws RecognitionException {
		SleighParser.pexpression2_operands_return retval = new SleighParser.pexpression2_operands_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LPAREN219=null;
		Token COMMA221=null;
		Token RPAREN223=null;
		ParserRuleReturnScope pexpression2220 =null;
		ParserRuleReturnScope pexpression2222 =null;

		CommonTree LPAREN219_tree=null;
		CommonTree COMMA221_tree=null;
		CommonTree RPAREN223_tree=null;

		try {
			// ghidra/sleigh/grammar/SleighParser.g:522:2: ( LPAREN ! ( pexpression2 ( COMMA ! pexpression2 )* )? RPAREN !)
			// ghidra/sleigh/grammar/SleighParser.g:522:4: LPAREN ! ( pexpression2 ( COMMA ! pexpression2 )* )? RPAREN !
			{
			root_0 = (CommonTree)adaptor.nil();


			LPAREN219=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_pexpression2_operands3074); if (state.failed) return retval;
			// ghidra/sleigh/grammar/SleighParser.g:522:12: ( pexpression2 ( COMMA ! pexpression2 )* )?
			int alt76=2;
			int LA76_0 = input.LA(1);
			if ( (LA76_0==BIN_INT||LA76_0==DEC_INT||(LA76_0 >= HEX_INT && LA76_0 <= KEY_WORDSIZE)||(LA76_0 >= LPAREN && LA76_0 <= MINUS)||LA76_0==TILDE) ) {
				alt76=1;
			}
			switch (alt76) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:522:13: pexpression2 ( COMMA ! pexpression2 )*
					{
					pushFollow(FOLLOW_pexpression2_in_pexpression2_operands3078);
					pexpression2220=pexpression2();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2220.getTree());

					// ghidra/sleigh/grammar/SleighParser.g:522:26: ( COMMA ! pexpression2 )*
					loop75:
					while (true) {
						int alt75=2;
						int LA75_0 = input.LA(1);
						if ( (LA75_0==COMMA) ) {
							alt75=1;
						}

						switch (alt75) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:522:27: COMMA ! pexpression2
							{
							COMMA221=(Token)match(input,COMMA,FOLLOW_COMMA_in_pexpression2_operands3081); if (state.failed) return retval;
							pushFollow(FOLLOW_pexpression2_in_pexpression2_operands3084);
							pexpression2222=pexpression2();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2222.getTree());

							}
							break;

						default :
							break loop75;
						}
					}

					}
					break;

			}

			RPAREN223=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_pexpression2_operands3091); if (state.failed) return retval;
			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_operands"


	public static class pexpression2_term_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_term"
	// ghidra/sleigh/grammar/SleighParser.g:525:1: pexpression2_term : ( identifier | integer |lc= LPAREN pexpression2 RPAREN -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression2 ) );
	public final SleighParser.pexpression2_term_return pexpression2_term() throws RecognitionException {
		SleighParser.pexpression2_term_return retval = new SleighParser.pexpression2_term_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token RPAREN227=null;
		ParserRuleReturnScope identifier224 =null;
		ParserRuleReturnScope integer225 =null;
		ParserRuleReturnScope pexpression2226 =null;

		CommonTree lc_tree=null;
		CommonTree RPAREN227_tree=null;
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleSubtreeStream stream_pexpression2=new RewriteRuleSubtreeStream(adaptor,"rule pexpression2");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:526:2: ( identifier | integer |lc= LPAREN pexpression2 RPAREN -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression2 ) )
			int alt77=3;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
			case KEY_ALIGNMENT:
			case KEY_ATTACH:
			case KEY_BIG:
			case KEY_BITRANGE:
			case KEY_BUILD:
			case KEY_CALL:
			case KEY_CONTEXT:
			case KEY_CROSSBUILD:
			case KEY_DEC:
			case KEY_DEFAULT:
			case KEY_DEFINE:
			case KEY_ENDIAN:
			case KEY_EXPORT:
			case KEY_GOTO:
			case KEY_HEX:
			case KEY_LITTLE:
			case KEY_LOCAL:
			case KEY_MACRO:
			case KEY_NAMES:
			case KEY_NOFLOW:
			case KEY_OFFSET:
			case KEY_PCODEOP:
			case KEY_RETURN:
			case KEY_SIGNED:
			case KEY_SIZE:
			case KEY_SPACE:
			case KEY_TOKEN:
			case KEY_TYPE:
			case KEY_UNIMPL:
			case KEY_VALUES:
			case KEY_VARIABLES:
			case KEY_WORDSIZE:
				{
				alt77=1;
				}
				break;
			case BIN_INT:
			case DEC_INT:
			case HEX_INT:
				{
				alt77=2;
				}
				break;
			case LPAREN:
				{
				alt77=3;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 77, 0, input);
				throw nvae;
			}
			switch (alt77) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:526:4: identifier
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_identifier_in_pexpression2_term3103);
					identifier224=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier224.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:527:4: integer
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_integer_in_pexpression2_term3108);
					integer225=integer();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, integer225.getTree());

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:528:4: lc= LPAREN pexpression2 RPAREN
					{
					lc=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_pexpression2_term3115); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LPAREN.add(lc);

					pushFollow(FOLLOW_pexpression2_in_pexpression2_term3117);
					pexpression2226=pexpression2();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_pexpression2.add(pexpression2226.getTree());
					RPAREN227=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_pexpression2_term3119); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RPAREN.add(RPAREN227);

					// AST REWRITE
					// elements: pexpression2
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 528:34: -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression2 )
					{
						// ghidra/sleigh/grammar/SleighParser.g:528:37: ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression2 )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PARENTHESIZED, lc, "(...)"), root_1);
						adaptor.addChild(root_1, stream_pexpression2.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_term"


	public static class qstring_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "qstring"
	// ghidra/sleigh/grammar/SleighParser.g:531:1: qstring : lc= QSTRING -> ^( OP_QSTRING[$lc, \"QSTRING\"] QSTRING ) ;
	public final SleighParser.qstring_return qstring() throws RecognitionException {
		SleighParser.qstring_return retval = new SleighParser.qstring_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_QSTRING=new RewriteRuleTokenStream(adaptor,"token QSTRING");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:532:2: (lc= QSTRING -> ^( OP_QSTRING[$lc, \"QSTRING\"] QSTRING ) )
			// ghidra/sleigh/grammar/SleighParser.g:532:4: lc= QSTRING
			{
			lc=(Token)match(input,QSTRING,FOLLOW_QSTRING_in_qstring3141); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_QSTRING.add(lc);

			// AST REWRITE
			// elements: QSTRING
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 532:15: -> ^( OP_QSTRING[$lc, \"QSTRING\"] QSTRING )
			{
				// ghidra/sleigh/grammar/SleighParser.g:532:18: ^( OP_QSTRING[$lc, \"QSTRING\"] QSTRING )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_QSTRING, lc, "QSTRING"), root_1);
				adaptor.addChild(root_1, stream_QSTRING.nextNode());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "qstring"


	public static class id_or_wild_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "id_or_wild"
	// ghidra/sleigh/grammar/SleighParser.g:535:1: id_or_wild : ( identifier | wildcard );
	public final SleighParser.id_or_wild_return id_or_wild() throws RecognitionException {
		SleighParser.id_or_wild_return retval = new SleighParser.id_or_wild_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier228 =null;
		ParserRuleReturnScope wildcard229 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:536:2: ( identifier | wildcard )
			int alt78=2;
			int LA78_0 = input.LA(1);
			if ( ((LA78_0 >= IDENTIFIER && LA78_0 <= KEY_WORDSIZE)) ) {
				alt78=1;
			}
			else if ( (LA78_0==UNDERSCORE) ) {
				alt78=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 78, 0, input);
				throw nvae;
			}

			switch (alt78) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:536:4: identifier
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_identifier_in_id_or_wild3161);
					identifier228=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier228.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:537:4: wildcard
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_wildcard_in_id_or_wild3166);
					wildcard229=wildcard();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, wildcard229.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "id_or_wild"


	public static class wildcard_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "wildcard"
	// ghidra/sleigh/grammar/SleighParser.g:540:1: wildcard : lc= UNDERSCORE -> OP_WILDCARD[$lc] ;
	public final SleighParser.wildcard_return wildcard() throws RecognitionException {
		SleighParser.wildcard_return retval = new SleighParser.wildcard_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_UNDERSCORE=new RewriteRuleTokenStream(adaptor,"token UNDERSCORE");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:541:2: (lc= UNDERSCORE -> OP_WILDCARD[$lc] )
			// ghidra/sleigh/grammar/SleighParser.g:541:4: lc= UNDERSCORE
			{
			lc=(Token)match(input,UNDERSCORE,FOLLOW_UNDERSCORE_in_wildcard3179); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_UNDERSCORE.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 541:19: -> OP_WILDCARD[$lc]
			{
				adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_WILDCARD, lc));
			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "wildcard"


	public static class identifier_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "identifier"
	// ghidra/sleigh/grammar/SleighParser.g:544:1: identifier : ( strict_id | key_as_id );
	public final SleighParser.identifier_return identifier() throws RecognitionException {
		SleighParser.identifier_return retval = new SleighParser.identifier_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope strict_id230 =null;
		ParserRuleReturnScope key_as_id231 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:545:2: ( strict_id | key_as_id )
			int alt79=2;
			int LA79_0 = input.LA(1);
			if ( (LA79_0==IDENTIFIER) ) {
				alt79=1;
			}
			else if ( ((LA79_0 >= KEY_ALIGNMENT && LA79_0 <= KEY_WORDSIZE)) ) {
				alt79=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 79, 0, input);
				throw nvae;
			}

			switch (alt79) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:545:4: strict_id
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_strict_id_in_identifier3196);
					strict_id230=strict_id();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, strict_id230.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:546:4: key_as_id
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_key_as_id_in_identifier3201);
					key_as_id231=key_as_id();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, key_as_id231.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "identifier"


	public static class key_as_id_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "key_as_id"
	// ghidra/sleigh/grammar/SleighParser.g:549:1: key_as_id : (lc= KEY_ALIGNMENT -> ^( OP_IDENTIFIER[$lc, \"KEY_ALIGNMENT\"] KEY_ALIGNMENT ) |lc= KEY_ATTACH -> ^( OP_IDENTIFIER[$lc, \"KEY_ATTACH\"] KEY_ATTACH ) |lc= KEY_BIG -> ^( OP_IDENTIFIER[$lc, \"KEY_BIG\"] KEY_BIG ) |lc= KEY_BITRANGE -> ^( OP_IDENTIFIER[$lc, \"KEY_BITRANGE\"] KEY_BITRANGE ) |lc= KEY_BUILD -> ^( OP_IDENTIFIER[$lc, \"KEY_BUILD\"] KEY_BUILD ) |lc= KEY_CALL -> ^( OP_IDENTIFIER[$lc, \"KEY_CALL\"] KEY_CALL ) |lc= KEY_CONTEXT -> ^( OP_IDENTIFIER[$lc, \"KEY_CONTEXT\"] KEY_CONTEXT ) |lc= KEY_CROSSBUILD -> ^( OP_IDENTIFIER[$lc, \"KEY_CROSSBUILD\"] KEY_CROSSBUILD ) |lc= KEY_DEC -> ^( OP_IDENTIFIER[$lc, \"KEY_DEC\"] KEY_DEC ) |lc= KEY_DEFAULT -> ^( OP_IDENTIFIER[$lc, \"KEY_DEFAULT\"] KEY_DEFAULT ) |lc= KEY_DEFINE -> ^( OP_IDENTIFIER[$lc, \"KEY_DEFINE\"] KEY_DEFINE ) |lc= KEY_ENDIAN -> ^( OP_IDENTIFIER[$lc, \"KEY_ENDIAN\"] KEY_ENDIAN ) |lc= KEY_EXPORT -> ^( OP_IDENTIFIER[$lc, \"KEY_EXPORT\"] KEY_EXPORT ) |lc= KEY_GOTO -> ^( OP_IDENTIFIER[$lc, \"KEY_GOTO\"] KEY_GOTO ) |lc= KEY_HEX -> ^( OP_IDENTIFIER[$lc, \"KEY_HEX\"] KEY_HEX ) |lc= KEY_LITTLE -> ^( OP_IDENTIFIER[$lc, \"KEY_LITTLE\"] KEY_LITTLE ) |lc= KEY_LOCAL -> ^( OP_IDENTIFIER[$lc, \"KEY_LOCAL\"] KEY_LOCAL ) |lc= KEY_MACRO -> ^( OP_IDENTIFIER[$lc, \"KEY_MACRO\"] KEY_MACRO ) |lc= KEY_NAMES -> ^( OP_IDENTIFIER[$lc, \"KEY_NAMES\"] KEY_NAMES ) |lc= KEY_NOFLOW -> ^( OP_IDENTIFIER[$lc, \"KEY_NOFLOW\"] KEY_NOFLOW ) |lc= KEY_OFFSET -> ^( OP_IDENTIFIER[$lc, \"KEY_OFFSET\"] KEY_OFFSET ) |lc= KEY_PCODEOP -> ^( OP_IDENTIFIER[$lc, \"KEY_PCODEOP\"] KEY_PCODEOP ) |lc= KEY_RETURN -> ^( OP_IDENTIFIER[$lc, \"KEY_RETURN\"] KEY_RETURN ) |lc= KEY_SIGNED -> ^( OP_IDENTIFIER[$lc, \"KEY_SIGNED\"] KEY_SIGNED ) |lc= KEY_SIZE -> ^( OP_IDENTIFIER[$lc, \"KEY_SIZE\"] KEY_SIZE ) |lc= KEY_SPACE -> ^( OP_IDENTIFIER[$lc, \"KEY_SPACE\"] KEY_SPACE ) |lc= KEY_TOKEN -> ^( OP_IDENTIFIER[$lc, \"KEY_TOKEN\"] KEY_TOKEN ) |lc= KEY_TYPE -> ^( OP_IDENTIFIER[$lc, \"KEY_TYPE\"] KEY_TYPE ) |lc= KEY_UNIMPL -> ^( OP_IDENTIFIER[$lc, \"KEY_UNIMPL\"] KEY_UNIMPL ) |lc= KEY_VALUES -> ^( OP_IDENTIFIER[$lc, \"KEY_VALUES\"] KEY_VALUES ) |lc= KEY_VARIABLES -> ^( OP_IDENTIFIER[$lc, \"KEY_VARIABLES\"] KEY_VARIABLES ) |lc= KEY_WORDSIZE -> ^( OP_IDENTIFIER[$lc, \"KEY_WORDSIZE\"] KEY_WORDSIZE ) );
	public final SleighParser.key_as_id_return key_as_id() throws RecognitionException {
		SleighParser.key_as_id_return retval = new SleighParser.key_as_id_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_ENDIAN=new RewriteRuleTokenStream(adaptor,"token KEY_ENDIAN");
		RewriteRuleTokenStream stream_KEY_VALUES=new RewriteRuleTokenStream(adaptor,"token KEY_VALUES");
		RewriteRuleTokenStream stream_KEY_SIZE=new RewriteRuleTokenStream(adaptor,"token KEY_SIZE");
		RewriteRuleTokenStream stream_KEY_WORDSIZE=new RewriteRuleTokenStream(adaptor,"token KEY_WORDSIZE");
		RewriteRuleTokenStream stream_KEY_UNIMPL=new RewriteRuleTokenStream(adaptor,"token KEY_UNIMPL");
		RewriteRuleTokenStream stream_KEY_BITRANGE=new RewriteRuleTokenStream(adaptor,"token KEY_BITRANGE");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleTokenStream stream_KEY_EXPORT=new RewriteRuleTokenStream(adaptor,"token KEY_EXPORT");
		RewriteRuleTokenStream stream_KEY_BUILD=new RewriteRuleTokenStream(adaptor,"token KEY_BUILD");
		RewriteRuleTokenStream stream_KEY_CALL=new RewriteRuleTokenStream(adaptor,"token KEY_CALL");
		RewriteRuleTokenStream stream_KEY_GOTO=new RewriteRuleTokenStream(adaptor,"token KEY_GOTO");
		RewriteRuleTokenStream stream_KEY_VARIABLES=new RewriteRuleTokenStream(adaptor,"token KEY_VARIABLES");
		RewriteRuleTokenStream stream_KEY_BIG=new RewriteRuleTokenStream(adaptor,"token KEY_BIG");
		RewriteRuleTokenStream stream_KEY_DEFAULT=new RewriteRuleTokenStream(adaptor,"token KEY_DEFAULT");
		RewriteRuleTokenStream stream_KEY_ATTACH=new RewriteRuleTokenStream(adaptor,"token KEY_ATTACH");
		RewriteRuleTokenStream stream_KEY_DEC=new RewriteRuleTokenStream(adaptor,"token KEY_DEC");
		RewriteRuleTokenStream stream_KEY_NAMES=new RewriteRuleTokenStream(adaptor,"token KEY_NAMES");
		RewriteRuleTokenStream stream_KEY_CONTEXT=new RewriteRuleTokenStream(adaptor,"token KEY_CONTEXT");
		RewriteRuleTokenStream stream_KEY_OFFSET=new RewriteRuleTokenStream(adaptor,"token KEY_OFFSET");
		RewriteRuleTokenStream stream_KEY_SIGNED=new RewriteRuleTokenStream(adaptor,"token KEY_SIGNED");
		RewriteRuleTokenStream stream_KEY_MACRO=new RewriteRuleTokenStream(adaptor,"token KEY_MACRO");
		RewriteRuleTokenStream stream_KEY_NOFLOW=new RewriteRuleTokenStream(adaptor,"token KEY_NOFLOW");
		RewriteRuleTokenStream stream_KEY_TOKEN=new RewriteRuleTokenStream(adaptor,"token KEY_TOKEN");
		RewriteRuleTokenStream stream_KEY_CROSSBUILD=new RewriteRuleTokenStream(adaptor,"token KEY_CROSSBUILD");
		RewriteRuleTokenStream stream_KEY_LOCAL=new RewriteRuleTokenStream(adaptor,"token KEY_LOCAL");
		RewriteRuleTokenStream stream_KEY_PCODEOP=new RewriteRuleTokenStream(adaptor,"token KEY_PCODEOP");
		RewriteRuleTokenStream stream_KEY_ALIGNMENT=new RewriteRuleTokenStream(adaptor,"token KEY_ALIGNMENT");
		RewriteRuleTokenStream stream_KEY_LITTLE=new RewriteRuleTokenStream(adaptor,"token KEY_LITTLE");
		RewriteRuleTokenStream stream_KEY_SPACE=new RewriteRuleTokenStream(adaptor,"token KEY_SPACE");
		RewriteRuleTokenStream stream_KEY_TYPE=new RewriteRuleTokenStream(adaptor,"token KEY_TYPE");
		RewriteRuleTokenStream stream_KEY_HEX=new RewriteRuleTokenStream(adaptor,"token KEY_HEX");
		RewriteRuleTokenStream stream_KEY_RETURN=new RewriteRuleTokenStream(adaptor,"token KEY_RETURN");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:550:2: (lc= KEY_ALIGNMENT -> ^( OP_IDENTIFIER[$lc, \"KEY_ALIGNMENT\"] KEY_ALIGNMENT ) |lc= KEY_ATTACH -> ^( OP_IDENTIFIER[$lc, \"KEY_ATTACH\"] KEY_ATTACH ) |lc= KEY_BIG -> ^( OP_IDENTIFIER[$lc, \"KEY_BIG\"] KEY_BIG ) |lc= KEY_BITRANGE -> ^( OP_IDENTIFIER[$lc, \"KEY_BITRANGE\"] KEY_BITRANGE ) |lc= KEY_BUILD -> ^( OP_IDENTIFIER[$lc, \"KEY_BUILD\"] KEY_BUILD ) |lc= KEY_CALL -> ^( OP_IDENTIFIER[$lc, \"KEY_CALL\"] KEY_CALL ) |lc= KEY_CONTEXT -> ^( OP_IDENTIFIER[$lc, \"KEY_CONTEXT\"] KEY_CONTEXT ) |lc= KEY_CROSSBUILD -> ^( OP_IDENTIFIER[$lc, \"KEY_CROSSBUILD\"] KEY_CROSSBUILD ) |lc= KEY_DEC -> ^( OP_IDENTIFIER[$lc, \"KEY_DEC\"] KEY_DEC ) |lc= KEY_DEFAULT -> ^( OP_IDENTIFIER[$lc, \"KEY_DEFAULT\"] KEY_DEFAULT ) |lc= KEY_DEFINE -> ^( OP_IDENTIFIER[$lc, \"KEY_DEFINE\"] KEY_DEFINE ) |lc= KEY_ENDIAN -> ^( OP_IDENTIFIER[$lc, \"KEY_ENDIAN\"] KEY_ENDIAN ) |lc= KEY_EXPORT -> ^( OP_IDENTIFIER[$lc, \"KEY_EXPORT\"] KEY_EXPORT ) |lc= KEY_GOTO -> ^( OP_IDENTIFIER[$lc, \"KEY_GOTO\"] KEY_GOTO ) |lc= KEY_HEX -> ^( OP_IDENTIFIER[$lc, \"KEY_HEX\"] KEY_HEX ) |lc= KEY_LITTLE -> ^( OP_IDENTIFIER[$lc, \"KEY_LITTLE\"] KEY_LITTLE ) |lc= KEY_LOCAL -> ^( OP_IDENTIFIER[$lc, \"KEY_LOCAL\"] KEY_LOCAL ) |lc= KEY_MACRO -> ^( OP_IDENTIFIER[$lc, \"KEY_MACRO\"] KEY_MACRO ) |lc= KEY_NAMES -> ^( OP_IDENTIFIER[$lc, \"KEY_NAMES\"] KEY_NAMES ) |lc= KEY_NOFLOW -> ^( OP_IDENTIFIER[$lc, \"KEY_NOFLOW\"] KEY_NOFLOW ) |lc= KEY_OFFSET -> ^( OP_IDENTIFIER[$lc, \"KEY_OFFSET\"] KEY_OFFSET ) |lc= KEY_PCODEOP -> ^( OP_IDENTIFIER[$lc, \"KEY_PCODEOP\"] KEY_PCODEOP ) |lc= KEY_RETURN -> ^( OP_IDENTIFIER[$lc, \"KEY_RETURN\"] KEY_RETURN ) |lc= KEY_SIGNED -> ^( OP_IDENTIFIER[$lc, \"KEY_SIGNED\"] KEY_SIGNED ) |lc= KEY_SIZE -> ^( OP_IDENTIFIER[$lc, \"KEY_SIZE\"] KEY_SIZE ) |lc= KEY_SPACE -> ^( OP_IDENTIFIER[$lc, \"KEY_SPACE\"] KEY_SPACE ) |lc= KEY_TOKEN -> ^( OP_IDENTIFIER[$lc, \"KEY_TOKEN\"] KEY_TOKEN ) |lc= KEY_TYPE -> ^( OP_IDENTIFIER[$lc, \"KEY_TYPE\"] KEY_TYPE ) |lc= KEY_UNIMPL -> ^( OP_IDENTIFIER[$lc, \"KEY_UNIMPL\"] KEY_UNIMPL ) |lc= KEY_VALUES -> ^( OP_IDENTIFIER[$lc, \"KEY_VALUES\"] KEY_VALUES ) |lc= KEY_VARIABLES -> ^( OP_IDENTIFIER[$lc, \"KEY_VARIABLES\"] KEY_VARIABLES ) |lc= KEY_WORDSIZE -> ^( OP_IDENTIFIER[$lc, \"KEY_WORDSIZE\"] KEY_WORDSIZE ) )
			int alt80=32;
			switch ( input.LA(1) ) {
			case KEY_ALIGNMENT:
				{
				alt80=1;
				}
				break;
			case KEY_ATTACH:
				{
				alt80=2;
				}
				break;
			case KEY_BIG:
				{
				alt80=3;
				}
				break;
			case KEY_BITRANGE:
				{
				alt80=4;
				}
				break;
			case KEY_BUILD:
				{
				alt80=5;
				}
				break;
			case KEY_CALL:
				{
				alt80=6;
				}
				break;
			case KEY_CONTEXT:
				{
				alt80=7;
				}
				break;
			case KEY_CROSSBUILD:
				{
				alt80=8;
				}
				break;
			case KEY_DEC:
				{
				alt80=9;
				}
				break;
			case KEY_DEFAULT:
				{
				alt80=10;
				}
				break;
			case KEY_DEFINE:
				{
				alt80=11;
				}
				break;
			case KEY_ENDIAN:
				{
				alt80=12;
				}
				break;
			case KEY_EXPORT:
				{
				alt80=13;
				}
				break;
			case KEY_GOTO:
				{
				alt80=14;
				}
				break;
			case KEY_HEX:
				{
				alt80=15;
				}
				break;
			case KEY_LITTLE:
				{
				alt80=16;
				}
				break;
			case KEY_LOCAL:
				{
				alt80=17;
				}
				break;
			case KEY_MACRO:
				{
				alt80=18;
				}
				break;
			case KEY_NAMES:
				{
				alt80=19;
				}
				break;
			case KEY_NOFLOW:
				{
				alt80=20;
				}
				break;
			case KEY_OFFSET:
				{
				alt80=21;
				}
				break;
			case KEY_PCODEOP:
				{
				alt80=22;
				}
				break;
			case KEY_RETURN:
				{
				alt80=23;
				}
				break;
			case KEY_SIGNED:
				{
				alt80=24;
				}
				break;
			case KEY_SIZE:
				{
				alt80=25;
				}
				break;
			case KEY_SPACE:
				{
				alt80=26;
				}
				break;
			case KEY_TOKEN:
				{
				alt80=27;
				}
				break;
			case KEY_TYPE:
				{
				alt80=28;
				}
				break;
			case KEY_UNIMPL:
				{
				alt80=29;
				}
				break;
			case KEY_VALUES:
				{
				alt80=30;
				}
				break;
			case KEY_VARIABLES:
				{
				alt80=31;
				}
				break;
			case KEY_WORDSIZE:
				{
				alt80=32;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 80, 0, input);
				throw nvae;
			}
			switch (alt80) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:550:4: lc= KEY_ALIGNMENT
					{
					lc=(Token)match(input,KEY_ALIGNMENT,FOLLOW_KEY_ALIGNMENT_in_key_as_id3214); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_ALIGNMENT.add(lc);

					// AST REWRITE
					// elements: KEY_ALIGNMENT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 550:21: -> ^( OP_IDENTIFIER[$lc, \"KEY_ALIGNMENT\"] KEY_ALIGNMENT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:550:24: ^( OP_IDENTIFIER[$lc, \"KEY_ALIGNMENT\"] KEY_ALIGNMENT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_ALIGNMENT"), root_1);
						adaptor.addChild(root_1, stream_KEY_ALIGNMENT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:551:4: lc= KEY_ATTACH
					{
					lc=(Token)match(input,KEY_ATTACH,FOLLOW_KEY_ATTACH_in_key_as_id3230); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_ATTACH.add(lc);

					// AST REWRITE
					// elements: KEY_ATTACH
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 551:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_ATTACH\"] KEY_ATTACH )
					{
						// ghidra/sleigh/grammar/SleighParser.g:551:22: ^( OP_IDENTIFIER[$lc, \"KEY_ATTACH\"] KEY_ATTACH )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_ATTACH"), root_1);
						adaptor.addChild(root_1, stream_KEY_ATTACH.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:552:4: lc= KEY_BIG
					{
					lc=(Token)match(input,KEY_BIG,FOLLOW_KEY_BIG_in_key_as_id3247); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_BIG.add(lc);

					// AST REWRITE
					// elements: KEY_BIG
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 552:17: -> ^( OP_IDENTIFIER[$lc, \"KEY_BIG\"] KEY_BIG )
					{
						// ghidra/sleigh/grammar/SleighParser.g:552:20: ^( OP_IDENTIFIER[$lc, \"KEY_BIG\"] KEY_BIG )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_BIG"), root_1);
						adaptor.addChild(root_1, stream_KEY_BIG.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighParser.g:553:4: lc= KEY_BITRANGE
					{
					lc=(Token)match(input,KEY_BITRANGE,FOLLOW_KEY_BITRANGE_in_key_as_id3265); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_BITRANGE.add(lc);

					// AST REWRITE
					// elements: KEY_BITRANGE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 553:21: -> ^( OP_IDENTIFIER[$lc, \"KEY_BITRANGE\"] KEY_BITRANGE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:553:24: ^( OP_IDENTIFIER[$lc, \"KEY_BITRANGE\"] KEY_BITRANGE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_BITRANGE"), root_1);
						adaptor.addChild(root_1, stream_KEY_BITRANGE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighParser.g:554:4: lc= KEY_BUILD
					{
					lc=(Token)match(input,KEY_BUILD,FOLLOW_KEY_BUILD_in_key_as_id3282); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_BUILD.add(lc);

					// AST REWRITE
					// elements: KEY_BUILD
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 554:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_BUILD\"] KEY_BUILD )
					{
						// ghidra/sleigh/grammar/SleighParser.g:554:21: ^( OP_IDENTIFIER[$lc, \"KEY_BUILD\"] KEY_BUILD )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_BUILD"), root_1);
						adaptor.addChild(root_1, stream_KEY_BUILD.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighParser.g:555:4: lc= KEY_CALL
					{
					lc=(Token)match(input,KEY_CALL,FOLLOW_KEY_CALL_in_key_as_id3299); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_CALL.add(lc);

					// AST REWRITE
					// elements: KEY_CALL
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 555:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_CALL\"] KEY_CALL )
					{
						// ghidra/sleigh/grammar/SleighParser.g:555:21: ^( OP_IDENTIFIER[$lc, \"KEY_CALL\"] KEY_CALL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_CALL"), root_1);
						adaptor.addChild(root_1, stream_KEY_CALL.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighParser.g:556:4: lc= KEY_CONTEXT
					{
					lc=(Token)match(input,KEY_CONTEXT,FOLLOW_KEY_CONTEXT_in_key_as_id3318); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_CONTEXT.add(lc);

					// AST REWRITE
					// elements: KEY_CONTEXT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 556:20: -> ^( OP_IDENTIFIER[$lc, \"KEY_CONTEXT\"] KEY_CONTEXT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:556:23: ^( OP_IDENTIFIER[$lc, \"KEY_CONTEXT\"] KEY_CONTEXT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_CONTEXT"), root_1);
						adaptor.addChild(root_1, stream_KEY_CONTEXT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighParser.g:557:4: lc= KEY_CROSSBUILD
					{
					lc=(Token)match(input,KEY_CROSSBUILD,FOLLOW_KEY_CROSSBUILD_in_key_as_id3335); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_CROSSBUILD.add(lc);

					// AST REWRITE
					// elements: KEY_CROSSBUILD
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 557:22: -> ^( OP_IDENTIFIER[$lc, \"KEY_CROSSBUILD\"] KEY_CROSSBUILD )
					{
						// ghidra/sleigh/grammar/SleighParser.g:557:25: ^( OP_IDENTIFIER[$lc, \"KEY_CROSSBUILD\"] KEY_CROSSBUILD )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_CROSSBUILD"), root_1);
						adaptor.addChild(root_1, stream_KEY_CROSSBUILD.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighParser.g:558:4: lc= KEY_DEC
					{
					lc=(Token)match(input,KEY_DEC,FOLLOW_KEY_DEC_in_key_as_id3351); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEC.add(lc);

					// AST REWRITE
					// elements: KEY_DEC
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 558:17: -> ^( OP_IDENTIFIER[$lc, \"KEY_DEC\"] KEY_DEC )
					{
						// ghidra/sleigh/grammar/SleighParser.g:558:20: ^( OP_IDENTIFIER[$lc, \"KEY_DEC\"] KEY_DEC )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_DEC"), root_1);
						adaptor.addChild(root_1, stream_KEY_DEC.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighParser.g:559:4: lc= KEY_DEFAULT
					{
					lc=(Token)match(input,KEY_DEFAULT,FOLLOW_KEY_DEFAULT_in_key_as_id3370); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEFAULT.add(lc);

					// AST REWRITE
					// elements: KEY_DEFAULT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 559:20: -> ^( OP_IDENTIFIER[$lc, \"KEY_DEFAULT\"] KEY_DEFAULT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:559:23: ^( OP_IDENTIFIER[$lc, \"KEY_DEFAULT\"] KEY_DEFAULT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_DEFAULT"), root_1);
						adaptor.addChild(root_1, stream_KEY_DEFAULT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighParser.g:560:4: lc= KEY_DEFINE
					{
					lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_key_as_id3387); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

					// AST REWRITE
					// elements: KEY_DEFINE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 560:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_DEFINE\"] KEY_DEFINE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:560:22: ^( OP_IDENTIFIER[$lc, \"KEY_DEFINE\"] KEY_DEFINE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_DEFINE"), root_1);
						adaptor.addChild(root_1, stream_KEY_DEFINE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighParser.g:561:4: lc= KEY_ENDIAN
					{
					lc=(Token)match(input,KEY_ENDIAN,FOLLOW_KEY_ENDIAN_in_key_as_id3404); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_ENDIAN.add(lc);

					// AST REWRITE
					// elements: KEY_ENDIAN
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 561:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_ENDIAN\"] KEY_ENDIAN )
					{
						// ghidra/sleigh/grammar/SleighParser.g:561:22: ^( OP_IDENTIFIER[$lc, \"KEY_ENDIAN\"] KEY_ENDIAN )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_ENDIAN"), root_1);
						adaptor.addChild(root_1, stream_KEY_ENDIAN.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighParser.g:562:4: lc= KEY_EXPORT
					{
					lc=(Token)match(input,KEY_EXPORT,FOLLOW_KEY_EXPORT_in_key_as_id3421); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_EXPORT.add(lc);

					// AST REWRITE
					// elements: KEY_EXPORT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 562:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_EXPORT\"] KEY_EXPORT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:562:22: ^( OP_IDENTIFIER[$lc, \"KEY_EXPORT\"] KEY_EXPORT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_EXPORT"), root_1);
						adaptor.addChild(root_1, stream_KEY_EXPORT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 14 :
					// ghidra/sleigh/grammar/SleighParser.g:563:4: lc= KEY_GOTO
					{
					lc=(Token)match(input,KEY_GOTO,FOLLOW_KEY_GOTO_in_key_as_id3438); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_GOTO.add(lc);

					// AST REWRITE
					// elements: KEY_GOTO
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 563:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_GOTO\"] KEY_GOTO )
					{
						// ghidra/sleigh/grammar/SleighParser.g:563:21: ^( OP_IDENTIFIER[$lc, \"KEY_GOTO\"] KEY_GOTO )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_GOTO"), root_1);
						adaptor.addChild(root_1, stream_KEY_GOTO.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 15 :
					// ghidra/sleigh/grammar/SleighParser.g:564:4: lc= KEY_HEX
					{
					lc=(Token)match(input,KEY_HEX,FOLLOW_KEY_HEX_in_key_as_id3456); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_HEX.add(lc);

					// AST REWRITE
					// elements: KEY_HEX
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 564:17: -> ^( OP_IDENTIFIER[$lc, \"KEY_HEX\"] KEY_HEX )
					{
						// ghidra/sleigh/grammar/SleighParser.g:564:20: ^( OP_IDENTIFIER[$lc, \"KEY_HEX\"] KEY_HEX )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_HEX"), root_1);
						adaptor.addChild(root_1, stream_KEY_HEX.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 16 :
					// ghidra/sleigh/grammar/SleighParser.g:565:4: lc= KEY_LITTLE
					{
					lc=(Token)match(input,KEY_LITTLE,FOLLOW_KEY_LITTLE_in_key_as_id3474); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_LITTLE.add(lc);

					// AST REWRITE
					// elements: KEY_LITTLE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 565:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_LITTLE\"] KEY_LITTLE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:565:22: ^( OP_IDENTIFIER[$lc, \"KEY_LITTLE\"] KEY_LITTLE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_LITTLE"), root_1);
						adaptor.addChild(root_1, stream_KEY_LITTLE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 17 :
					// ghidra/sleigh/grammar/SleighParser.g:566:4: lc= KEY_LOCAL
					{
					lc=(Token)match(input,KEY_LOCAL,FOLLOW_KEY_LOCAL_in_key_as_id3491); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_LOCAL.add(lc);

					// AST REWRITE
					// elements: KEY_LOCAL
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 566:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_LOCAL\"] KEY_LOCAL )
					{
						// ghidra/sleigh/grammar/SleighParser.g:566:21: ^( OP_IDENTIFIER[$lc, \"KEY_LOCAL\"] KEY_LOCAL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_LOCAL"), root_1);
						adaptor.addChild(root_1, stream_KEY_LOCAL.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 18 :
					// ghidra/sleigh/grammar/SleighParser.g:567:4: lc= KEY_MACRO
					{
					lc=(Token)match(input,KEY_MACRO,FOLLOW_KEY_MACRO_in_key_as_id3508); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_MACRO.add(lc);

					// AST REWRITE
					// elements: KEY_MACRO
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 567:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_MACRO\"] KEY_MACRO )
					{
						// ghidra/sleigh/grammar/SleighParser.g:567:21: ^( OP_IDENTIFIER[$lc, \"KEY_MACRO\"] KEY_MACRO )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_MACRO"), root_1);
						adaptor.addChild(root_1, stream_KEY_MACRO.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 19 :
					// ghidra/sleigh/grammar/SleighParser.g:568:4: lc= KEY_NAMES
					{
					lc=(Token)match(input,KEY_NAMES,FOLLOW_KEY_NAMES_in_key_as_id3525); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_NAMES.add(lc);

					// AST REWRITE
					// elements: KEY_NAMES
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 568:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_NAMES\"] KEY_NAMES )
					{
						// ghidra/sleigh/grammar/SleighParser.g:568:21: ^( OP_IDENTIFIER[$lc, \"KEY_NAMES\"] KEY_NAMES )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_NAMES"), root_1);
						adaptor.addChild(root_1, stream_KEY_NAMES.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 20 :
					// ghidra/sleigh/grammar/SleighParser.g:569:4: lc= KEY_NOFLOW
					{
					lc=(Token)match(input,KEY_NOFLOW,FOLLOW_KEY_NOFLOW_in_key_as_id3542); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_NOFLOW.add(lc);

					// AST REWRITE
					// elements: KEY_NOFLOW
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 569:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_NOFLOW\"] KEY_NOFLOW )
					{
						// ghidra/sleigh/grammar/SleighParser.g:569:22: ^( OP_IDENTIFIER[$lc, \"KEY_NOFLOW\"] KEY_NOFLOW )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_NOFLOW"), root_1);
						adaptor.addChild(root_1, stream_KEY_NOFLOW.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 21 :
					// ghidra/sleigh/grammar/SleighParser.g:570:4: lc= KEY_OFFSET
					{
					lc=(Token)match(input,KEY_OFFSET,FOLLOW_KEY_OFFSET_in_key_as_id3559); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_OFFSET.add(lc);

					// AST REWRITE
					// elements: KEY_OFFSET
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 570:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_OFFSET\"] KEY_OFFSET )
					{
						// ghidra/sleigh/grammar/SleighParser.g:570:22: ^( OP_IDENTIFIER[$lc, \"KEY_OFFSET\"] KEY_OFFSET )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_OFFSET"), root_1);
						adaptor.addChild(root_1, stream_KEY_OFFSET.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 22 :
					// ghidra/sleigh/grammar/SleighParser.g:571:4: lc= KEY_PCODEOP
					{
					lc=(Token)match(input,KEY_PCODEOP,FOLLOW_KEY_PCODEOP_in_key_as_id3576); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_PCODEOP.add(lc);

					// AST REWRITE
					// elements: KEY_PCODEOP
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 571:20: -> ^( OP_IDENTIFIER[$lc, \"KEY_PCODEOP\"] KEY_PCODEOP )
					{
						// ghidra/sleigh/grammar/SleighParser.g:571:23: ^( OP_IDENTIFIER[$lc, \"KEY_PCODEOP\"] KEY_PCODEOP )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_PCODEOP"), root_1);
						adaptor.addChild(root_1, stream_KEY_PCODEOP.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 23 :
					// ghidra/sleigh/grammar/SleighParser.g:572:4: lc= KEY_RETURN
					{
					lc=(Token)match(input,KEY_RETURN,FOLLOW_KEY_RETURN_in_key_as_id3593); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_RETURN.add(lc);

					// AST REWRITE
					// elements: KEY_RETURN
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 572:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_RETURN\"] KEY_RETURN )
					{
						// ghidra/sleigh/grammar/SleighParser.g:572:22: ^( OP_IDENTIFIER[$lc, \"KEY_RETURN\"] KEY_RETURN )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_RETURN"), root_1);
						adaptor.addChild(root_1, stream_KEY_RETURN.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 24 :
					// ghidra/sleigh/grammar/SleighParser.g:573:4: lc= KEY_SIGNED
					{
					lc=(Token)match(input,KEY_SIGNED,FOLLOW_KEY_SIGNED_in_key_as_id3610); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_SIGNED.add(lc);

					// AST REWRITE
					// elements: KEY_SIGNED
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 573:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_SIGNED\"] KEY_SIGNED )
					{
						// ghidra/sleigh/grammar/SleighParser.g:573:22: ^( OP_IDENTIFIER[$lc, \"KEY_SIGNED\"] KEY_SIGNED )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_SIGNED"), root_1);
						adaptor.addChild(root_1, stream_KEY_SIGNED.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 25 :
					// ghidra/sleigh/grammar/SleighParser.g:574:4: lc= KEY_SIZE
					{
					lc=(Token)match(input,KEY_SIZE,FOLLOW_KEY_SIZE_in_key_as_id3627); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_SIZE.add(lc);

					// AST REWRITE
					// elements: KEY_SIZE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 574:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_SIZE\"] KEY_SIZE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:574:21: ^( OP_IDENTIFIER[$lc, \"KEY_SIZE\"] KEY_SIZE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_SIZE"), root_1);
						adaptor.addChild(root_1, stream_KEY_SIZE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 26 :
					// ghidra/sleigh/grammar/SleighParser.g:575:4: lc= KEY_SPACE
					{
					lc=(Token)match(input,KEY_SPACE,FOLLOW_KEY_SPACE_in_key_as_id3645); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_SPACE.add(lc);

					// AST REWRITE
					// elements: KEY_SPACE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 575:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_SPACE\"] KEY_SPACE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:575:21: ^( OP_IDENTIFIER[$lc, \"KEY_SPACE\"] KEY_SPACE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_SPACE"), root_1);
						adaptor.addChild(root_1, stream_KEY_SPACE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 27 :
					// ghidra/sleigh/grammar/SleighParser.g:576:4: lc= KEY_TOKEN
					{
					lc=(Token)match(input,KEY_TOKEN,FOLLOW_KEY_TOKEN_in_key_as_id3662); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_TOKEN.add(lc);

					// AST REWRITE
					// elements: KEY_TOKEN
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 576:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_TOKEN\"] KEY_TOKEN )
					{
						// ghidra/sleigh/grammar/SleighParser.g:576:21: ^( OP_IDENTIFIER[$lc, \"KEY_TOKEN\"] KEY_TOKEN )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_TOKEN"), root_1);
						adaptor.addChild(root_1, stream_KEY_TOKEN.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 28 :
					// ghidra/sleigh/grammar/SleighParser.g:577:4: lc= KEY_TYPE
					{
					lc=(Token)match(input,KEY_TYPE,FOLLOW_KEY_TYPE_in_key_as_id3679); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_TYPE.add(lc);

					// AST REWRITE
					// elements: KEY_TYPE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 577:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_TYPE\"] KEY_TYPE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:577:21: ^( OP_IDENTIFIER[$lc, \"KEY_TYPE\"] KEY_TYPE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_TYPE"), root_1);
						adaptor.addChild(root_1, stream_KEY_TYPE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 29 :
					// ghidra/sleigh/grammar/SleighParser.g:578:4: lc= KEY_UNIMPL
					{
					lc=(Token)match(input,KEY_UNIMPL,FOLLOW_KEY_UNIMPL_in_key_as_id3697); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_UNIMPL.add(lc);

					// AST REWRITE
					// elements: KEY_UNIMPL
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 578:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_UNIMPL\"] KEY_UNIMPL )
					{
						// ghidra/sleigh/grammar/SleighParser.g:578:22: ^( OP_IDENTIFIER[$lc, \"KEY_UNIMPL\"] KEY_UNIMPL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_UNIMPL"), root_1);
						adaptor.addChild(root_1, stream_KEY_UNIMPL.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 30 :
					// ghidra/sleigh/grammar/SleighParser.g:579:4: lc= KEY_VALUES
					{
					lc=(Token)match(input,KEY_VALUES,FOLLOW_KEY_VALUES_in_key_as_id3714); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_VALUES.add(lc);

					// AST REWRITE
					// elements: KEY_VALUES
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 579:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_VALUES\"] KEY_VALUES )
					{
						// ghidra/sleigh/grammar/SleighParser.g:579:22: ^( OP_IDENTIFIER[$lc, \"KEY_VALUES\"] KEY_VALUES )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_VALUES"), root_1);
						adaptor.addChild(root_1, stream_KEY_VALUES.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 31 :
					// ghidra/sleigh/grammar/SleighParser.g:580:4: lc= KEY_VARIABLES
					{
					lc=(Token)match(input,KEY_VARIABLES,FOLLOW_KEY_VARIABLES_in_key_as_id3731); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_VARIABLES.add(lc);

					// AST REWRITE
					// elements: KEY_VARIABLES
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 580:21: -> ^( OP_IDENTIFIER[$lc, \"KEY_VARIABLES\"] KEY_VARIABLES )
					{
						// ghidra/sleigh/grammar/SleighParser.g:580:24: ^( OP_IDENTIFIER[$lc, \"KEY_VARIABLES\"] KEY_VARIABLES )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_VARIABLES"), root_1);
						adaptor.addChild(root_1, stream_KEY_VARIABLES.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 32 :
					// ghidra/sleigh/grammar/SleighParser.g:581:4: lc= KEY_WORDSIZE
					{
					lc=(Token)match(input,KEY_WORDSIZE,FOLLOW_KEY_WORDSIZE_in_key_as_id3747); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_WORDSIZE.add(lc);

					// AST REWRITE
					// elements: KEY_WORDSIZE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 581:21: -> ^( OP_IDENTIFIER[$lc, \"KEY_WORDSIZE\"] KEY_WORDSIZE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:581:24: ^( OP_IDENTIFIER[$lc, \"KEY_WORDSIZE\"] KEY_WORDSIZE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_WORDSIZE"), root_1);
						adaptor.addChild(root_1, stream_KEY_WORDSIZE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "key_as_id"


	public static class strict_id_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "strict_id"
	// ghidra/sleigh/grammar/SleighParser.g:584:1: strict_id : lc= IDENTIFIER -> ^( OP_IDENTIFIER[$lc, \"IDENTIFIER\"] IDENTIFIER ) ;
	public final SleighParser.strict_id_return strict_id() throws RecognitionException {
		SleighParser.strict_id_return retval = new SleighParser.strict_id_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_IDENTIFIER=new RewriteRuleTokenStream(adaptor,"token IDENTIFIER");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:585:2: (lc= IDENTIFIER -> ^( OP_IDENTIFIER[$lc, \"IDENTIFIER\"] IDENTIFIER ) )
			// ghidra/sleigh/grammar/SleighParser.g:585:4: lc= IDENTIFIER
			{
			lc=(Token)match(input,IDENTIFIER,FOLLOW_IDENTIFIER_in_strict_id3770); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_IDENTIFIER.add(lc);

			// AST REWRITE
			// elements: IDENTIFIER
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 585:19: -> ^( OP_IDENTIFIER[$lc, \"IDENTIFIER\"] IDENTIFIER )
			{
				// ghidra/sleigh/grammar/SleighParser.g:585:22: ^( OP_IDENTIFIER[$lc, \"IDENTIFIER\"] IDENTIFIER )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "IDENTIFIER"), root_1);
				adaptor.addChild(root_1, stream_IDENTIFIER.nextNode());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "strict_id"


	public static class integer_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "integer"
	// ghidra/sleigh/grammar/SleighParser.g:588:1: integer : (lc= HEX_INT -> ^( OP_HEX_CONSTANT[$lc, \"HEX_INT\"] HEX_INT ) |lc= DEC_INT -> ^( OP_DEC_CONSTANT[$lc, \"DEC_INT\"] DEC_INT ) |lc= BIN_INT -> ^( OP_BIN_CONSTANT[$lc, \"BIN_INT\"] BIN_INT ) );
	public final SleighParser.integer_return integer() throws RecognitionException {
		SleighParser.integer_return retval = new SleighParser.integer_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_DEC_INT=new RewriteRuleTokenStream(adaptor,"token DEC_INT");
		RewriteRuleTokenStream stream_BIN_INT=new RewriteRuleTokenStream(adaptor,"token BIN_INT");
		RewriteRuleTokenStream stream_HEX_INT=new RewriteRuleTokenStream(adaptor,"token HEX_INT");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:589:2: (lc= HEX_INT -> ^( OP_HEX_CONSTANT[$lc, \"HEX_INT\"] HEX_INT ) |lc= DEC_INT -> ^( OP_DEC_CONSTANT[$lc, \"DEC_INT\"] DEC_INT ) |lc= BIN_INT -> ^( OP_BIN_CONSTANT[$lc, \"BIN_INT\"] BIN_INT ) )
			int alt81=3;
			switch ( input.LA(1) ) {
			case HEX_INT:
				{
				alt81=1;
				}
				break;
			case DEC_INT:
				{
				alt81=2;
				}
				break;
			case BIN_INT:
				{
				alt81=3;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 81, 0, input);
				throw nvae;
			}
			switch (alt81) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:589:4: lc= HEX_INT
					{
					lc=(Token)match(input,HEX_INT,FOLLOW_HEX_INT_in_integer3793); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_HEX_INT.add(lc);

					// AST REWRITE
					// elements: HEX_INT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 589:15: -> ^( OP_HEX_CONSTANT[$lc, \"HEX_INT\"] HEX_INT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:589:18: ^( OP_HEX_CONSTANT[$lc, \"HEX_INT\"] HEX_INT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_HEX_CONSTANT, lc, "HEX_INT"), root_1);
						adaptor.addChild(root_1, stream_HEX_INT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:590:4: lc= DEC_INT
					{
					lc=(Token)match(input,DEC_INT,FOLLOW_DEC_INT_in_integer3809); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_DEC_INT.add(lc);

					// AST REWRITE
					// elements: DEC_INT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 590:15: -> ^( OP_DEC_CONSTANT[$lc, \"DEC_INT\"] DEC_INT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:590:18: ^( OP_DEC_CONSTANT[$lc, \"DEC_INT\"] DEC_INT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DEC_CONSTANT, lc, "DEC_INT"), root_1);
						adaptor.addChild(root_1, stream_DEC_INT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:591:4: lc= BIN_INT
					{
					lc=(Token)match(input,BIN_INT,FOLLOW_BIN_INT_in_integer3825); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_BIN_INT.add(lc);

					// AST REWRITE
					// elements: BIN_INT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 591:15: -> ^( OP_BIN_CONSTANT[$lc, \"BIN_INT\"] BIN_INT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:591:18: ^( OP_BIN_CONSTANT[$lc, \"BIN_INT\"] BIN_INT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BIN_CONSTANT, lc, "BIN_INT"), root_1);
						adaptor.addChild(root_1, stream_BIN_INT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "integer"

	// $ANTLR start synpred1_SleighParser
	public final void synpred1_SleighParser_fragment() throws RecognitionException {
		// ghidra/sleigh/grammar/SleighParser.g:338:4: ( pequation_atomic ELLIPSIS )
		// ghidra/sleigh/grammar/SleighParser.g:338:5: pequation_atomic ELLIPSIS
		{
		pushFollow(FOLLOW_pequation_atomic_in_synpred1_SleighParser2031);
		pequation_atomic();
		state._fsp--;
		if (state.failed) return;

		match(input,ELLIPSIS,FOLLOW_ELLIPSIS_in_synpred1_SleighParser2033); if (state.failed) return;

		}

	}
	// $ANTLR end synpred1_SleighParser

	// Delegated rules
	public SleighParser_SemanticParser.expr_booland_return expr_booland() throws RecognitionException { return gSemanticParser.expr_booland(); }

	public SleighParser_SemanticParser.declaration_return declaration() throws RecognitionException { return gSemanticParser.declaration(); }

	public SleighParser_SemanticParser.section_def_return section_def() throws RecognitionException { return gSemanticParser.section_def(); }

	public SleighParser_SemanticParser.expr_term_return expr_term() throws RecognitionException { return gSemanticParser.expr_term(); }

	public SleighParser_SemanticParser.expr_and_op_return expr_and_op() throws RecognitionException { return gSemanticParser.expr_and_op(); }

	public SleighParser_SemanticParser.booland_op_return booland_op() throws RecognitionException { return gSemanticParser.booland_op(); }

	public SleighParser_SemanticParser.code_block_return code_block() throws RecognitionException { return gSemanticParser.code_block(); }

	public SleighParser_SemanticParser.expr_add_return expr_add() throws RecognitionException { return gSemanticParser.expr_add(); }

	public SleighParser_DisplayParser.whitespace_return whitespace() throws RecognitionException { return gDisplayParser.whitespace(); }

	public SleighParser_SemanticParser.statements_return statements() throws RecognitionException { return gSemanticParser.statements(); }

	public SleighParser_SemanticParser.sembitrange_return sembitrange() throws RecognitionException { return gSemanticParser.sembitrange(); }

	public SleighParser_SemanticParser.assignment_return assignment() throws RecognitionException { return gSemanticParser.assignment(); }

	public SleighParser_SemanticParser.expr_shift_return expr_shift() throws RecognitionException { return gSemanticParser.expr_shift(); }

	public SleighParser_DisplayParser.special_return special() throws RecognitionException { return gDisplayParser.special(); }

	public SleighParser_SemanticParser.semantic_return semantic() throws RecognitionException { return gSemanticParser.semantic(); }

	public SleighParser_SemanticParser.sizedexport_return sizedexport() throws RecognitionException { return gSemanticParser.sizedexport(); }

	public SleighParser_SemanticParser.expr_func_return expr_func() throws RecognitionException { return gSemanticParser.expr_func(); }

	public SleighParser_SemanticParser.constant_return constant() throws RecognitionException { return gSemanticParser.constant(); }

	public SleighParser_SemanticParser.label_return label() throws RecognitionException { return gSemanticParser.label(); }

	public SleighParser_SemanticParser.statement_return statement() throws RecognitionException { return gSemanticParser.statement(); }

	public SleighParser_SemanticParser.build_stmt_return build_stmt() throws RecognitionException { return gSemanticParser.build_stmt(); }

	public SleighParser_SemanticParser.expr_apply_return expr_apply() throws RecognitionException { return gSemanticParser.expr_apply(); }

	public SleighParser_SemanticParser.add_op_return add_op() throws RecognitionException { return gSemanticParser.add_op(); }

	public SleighParser_SemanticParser.unary_op_return unary_op() throws RecognitionException { return gSemanticParser.unary_op(); }

	public SleighParser_SemanticParser.goto_stmt_return goto_stmt() throws RecognitionException { return gSemanticParser.goto_stmt(); }

	public SleighParser_SemanticParser.expr_mult_return expr_mult() throws RecognitionException { return gSemanticParser.expr_mult(); }

	public SleighParser_SemanticParser.expr_xor_return expr_xor() throws RecognitionException { return gSemanticParser.expr_xor(); }

	public SleighParser_SemanticParser.expr_or_return expr_or() throws RecognitionException { return gSemanticParser.expr_or(); }

	public SleighParser_DisplayParser.display_return display() throws RecognitionException { return gDisplayParser.display(); }

	public SleighParser_SemanticParser.varnode_return varnode() throws RecognitionException { return gSemanticParser.varnode(); }

	public SleighParser_SemanticParser.funcall_return funcall() throws RecognitionException { return gSemanticParser.funcall(); }

	public SleighParser_SemanticParser.expr_boolor_return expr_boolor() throws RecognitionException { return gSemanticParser.expr_boolor(); }

	public SleighParser_SemanticParser.expr_unary_return expr_unary() throws RecognitionException { return gSemanticParser.expr_unary(); }

	public SleighParser_DisplayParser.pieces_return pieces() throws RecognitionException { return gDisplayParser.pieces(); }

	public SleighParser_SemanticParser.expr_comp_return expr_comp() throws RecognitionException { return gSemanticParser.expr_comp(); }

	public SleighParser_SemanticParser.outererror_return outererror() throws RecognitionException { return gSemanticParser.outererror(); }

	public SleighParser_SemanticParser.expr_boolor_op_return expr_boolor_op() throws RecognitionException { return gSemanticParser.expr_boolor_op(); }

	public SleighParser_SemanticParser.call_stmt_return call_stmt() throws RecognitionException { return gSemanticParser.call_stmt(); }

	public SleighParser_SemanticParser.eq_op_return eq_op() throws RecognitionException { return gSemanticParser.eq_op(); }

	public SleighParser_SemanticParser.jumpdest_return jumpdest() throws RecognitionException { return gSemanticParser.jumpdest(); }

	public SleighParser_SemanticParser.lvalue_return lvalue() throws RecognitionException { return gSemanticParser.lvalue(); }

	public SleighParser_SemanticParser.shift_op_return shift_op() throws RecognitionException { return gSemanticParser.shift_op(); }

	public SleighParser_SemanticParser.expr_and_return expr_and() throws RecognitionException { return gSemanticParser.expr_and(); }

	public SleighParser_SemanticParser.expr_operands_return expr_operands() throws RecognitionException { return gSemanticParser.expr_operands(); }

	public SleighParser_SemanticParser.cond_stmt_return cond_stmt() throws RecognitionException { return gSemanticParser.cond_stmt(); }

	public SleighParser_DisplayParser.concatenate_return concatenate() throws RecognitionException { return gDisplayParser.concatenate(); }

	public SleighParser_SemanticParser.return_stmt_return return_stmt() throws RecognitionException { return gSemanticParser.return_stmt(); }

	public SleighParser_SemanticParser.export_return export() throws RecognitionException { return gSemanticParser.export(); }

	public SleighParser_SemanticParser.expr_return expr() throws RecognitionException { return gSemanticParser.expr(); }

	public SleighParser_SemanticParser.crossbuild_stmt_return crossbuild_stmt() throws RecognitionException { return gSemanticParser.crossbuild_stmt(); }

	public SleighParser_SemanticParser.compare_op_return compare_op() throws RecognitionException { return gSemanticParser.compare_op(); }

	public SleighParser_DisplayParser.printpiece_return printpiece() throws RecognitionException { return gDisplayParser.printpiece(); }

	public SleighParser_SemanticParser.expr_xor_op_return expr_xor_op() throws RecognitionException { return gSemanticParser.expr_xor_op(); }

	public SleighParser_SemanticParser.sizedstar_return sizedstar() throws RecognitionException { return gSemanticParser.sizedstar(); }

	public SleighParser_SemanticParser.expr_or_op_return expr_or_op() throws RecognitionException { return gSemanticParser.expr_or_op(); }

	public SleighParser_SemanticParser.expr_eq_return expr_eq() throws RecognitionException { return gSemanticParser.expr_eq(); }

	public SleighParser_SemanticParser.semanticbody_return semanticbody() throws RecognitionException { return gSemanticParser.semanticbody(); }

	public SleighParser_SemanticParser.mult_op_return mult_op() throws RecognitionException { return gSemanticParser.mult_op(); }

	public final boolean synpred1_SleighParser() {
		state.backtracking++;
		int start = input.mark();
		try {
			synpred1_SleighParser_fragment(); // can never throw exception
		} catch (RecognitionException re) {
			System.err.println("impossible: "+re);
		}
		boolean success = !state.failed;
		input.rewind(start);
		state.backtracking--;
		state.failed=false;
		return success;
	}



	public static final BitSet FOLLOW_endiandef_in_spec78 = new BitSet(new long[]{0xFFFFFF0000008000L,0x00000000000001FFL,0x0000000000000000L,0x0000000004000000L});
	public static final BitSet FOLLOW_definition_in_spec84 = new BitSet(new long[]{0xFFFFFF0000008000L,0x00000000000001FFL,0x0000000000000000L,0x0000000004000000L});
	public static final BitSet FOLLOW_constructorlike_in_spec90 = new BitSet(new long[]{0xFFFFFF0000008000L,0x00000000000001FFL,0x0000000000000000L,0x0000000004000000L});
	public static final BitSet FOLLOW_EOF_in_spec97 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_endiandef110 = new BitSet(new long[]{0x0010000000000000L});
	public static final BitSet FOLLOW_KEY_ENDIAN_in_endiandef112 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_endiandef114 = new BitSet(new long[]{0x0100080000000000L});
	public static final BitSet FOLLOW_endian_in_endiandef116 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_SEMI_in_endiandef118 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_BIG_in_endian140 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_LITTLE_in_endian152 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_aligndef_in_definition169 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_tokendef_in_definition174 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_contextdef_in_definition179 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_spacedef_in_definition184 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_varnodedef_in_definition189 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_bitrangedef_in_definition194 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_pcodeopdef_in_definition199 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_valueattach_in_definition204 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_nameattach_in_definition209 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_varattach_in_definition214 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_SEMI_in_definition217 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_aligndef231 = new BitSet(new long[]{0x0000020000000000L});
	public static final BitSet FOLLOW_KEY_ALIGNMENT_in_aligndef233 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_aligndef235 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_aligndef237 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_tokendef259 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000008L});
	public static final BitSet FOLLOW_KEY_TOKEN_in_tokendef261 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_tokendef263 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_LPAREN_in_tokendef265 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_tokendef267 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_RPAREN_in_tokendef271 = new BitSet(new long[]{0x0000010000000000L});
	public static final BitSet FOLLOW_fielddefs_in_tokendef273 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_tokendef296 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000008L});
	public static final BitSet FOLLOW_KEY_TOKEN_in_tokendef298 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_tokendef300 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_LPAREN_in_tokendef302 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_tokendef304 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_RPAREN_in_tokendef306 = new BitSet(new long[]{0x0010000000000000L});
	public static final BitSet FOLLOW_KEY_ENDIAN_in_tokendef310 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_tokendef312 = new BitSet(new long[]{0x0100080000000000L});
	public static final BitSet FOLLOW_endian_in_tokendef314 = new BitSet(new long[]{0x0000010000000000L});
	public static final BitSet FOLLOW_fielddefs_in_tokendef316 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_fielddef_in_fielddefs344 = new BitSet(new long[]{0x0000010000000002L});
	public static final BitSet FOLLOW_strict_id_in_fielddef366 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_fielddef370 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_LPAREN_in_fielddef372 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_fielddef376 = new BitSet(new long[]{0x0000000000010000L});
	public static final BitSet FOLLOW_COMMA_in_fielddef378 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_fielddef382 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_RPAREN_in_fielddef386 = new BitSet(new long[]{0x0082000000000000L,0x0000000000000001L});
	public static final BitSet FOLLOW_fieldmods_in_fielddef388 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_fieldmod_in_fieldmods418 = new BitSet(new long[]{0x0082000000000002L,0x0000000000000001L});
	public static final BitSet FOLLOW_KEY_SIGNED_in_fieldmod455 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_HEX_in_fieldmod472 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEC_in_fieldmod489 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_contextfielddef_in_contextfielddefs509 = new BitSet(new long[]{0xFFFFFF0000000002L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_contextfielddef531 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_contextfielddef535 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_LPAREN_in_contextfielddef537 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_contextfielddef541 = new BitSet(new long[]{0x0000000000010000L});
	public static final BitSet FOLLOW_COMMA_in_contextfielddef543 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_contextfielddef547 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_RPAREN_in_contextfielddef551 = new BitSet(new long[]{0x1082000000000000L,0x0000000000000001L});
	public static final BitSet FOLLOW_contextfieldmods_in_contextfielddef553 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_contextfieldmod_in_contextfieldmods588 = new BitSet(new long[]{0x1082000000000002L,0x0000000000000001L});
	public static final BitSet FOLLOW_KEY_SIGNED_in_contextfieldmod633 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_NOFLOW_in_contextfieldmod650 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_HEX_in_contextfieldmod667 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEC_in_contextfieldmod684 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_contextdef705 = new BitSet(new long[]{0x0000800000000000L});
	public static final BitSet FOLLOW_KEY_CONTEXT_in_contextdef709 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_contextdef711 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_contextfielddefs_in_contextdef713 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_spacedef738 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000004L});
	public static final BitSet FOLLOW_KEY_SPACE_in_spacedef740 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_spacedef742 = new BitSet(new long[]{0x0004000000000000L,0x0000000000000112L});
	public static final BitSet FOLLOW_spacemods_in_spacedef744 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_spacemod_in_spacemods768 = new BitSet(new long[]{0x0004000000000002L,0x0000000000000112L});
	public static final BitSet FOLLOW_typemod_in_spacemod790 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_sizemod_in_spacemod795 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_wordsizemod_in_spacemod800 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFAULT_in_spacemod807 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_TYPE_in_typemod825 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_typemod827 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_type_in_typemod829 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_type849 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_SIZE_in_sizemod862 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_sizemod864 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_sizemod866 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_WORDSIZE_in_wordsizemod888 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_wordsizemod890 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_wordsizemod892 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_varnodedef914 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_varnodedef916 = new BitSet(new long[]{0x2000000000000000L});
	public static final BitSet FOLLOW_KEY_OFFSET_in_varnodedef918 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_varnodedef920 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_varnodedef924 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_SIZE_in_varnodedef926 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_varnodedef930 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_varnodedef934 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000080000000000L});
	public static final BitSet FOLLOW_identifierlist_in_varnodedef936 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_bitrangedef969 = new BitSet(new long[]{0x0000100000000000L});
	public static final BitSet FOLLOW_KEY_BITRANGE_in_bitrangedef971 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_bitranges_in_bitrangedef973 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_bitrange_in_bitranges993 = new BitSet(new long[]{0xFFFFFF0000000002L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_bitrange1007 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_bitrange1011 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_bitrange1015 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_LBRACKET_in_bitrange1017 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_bitrange1021 = new BitSet(new long[]{0x0000000000010000L});
	public static final BitSet FOLLOW_COMMA_in_bitrange1023 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_bitrange1027 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000800000L});
	public static final BitSet FOLLOW_RBRACKET_in_bitrange1029 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_pcodeopdef1061 = new BitSet(new long[]{0x4000000000000000L});
	public static final BitSet FOLLOW_KEY_PCODEOP_in_pcodeopdef1065 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000080000000000L});
	public static final BitSet FOLLOW_identifierlist_in_pcodeopdef1067 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_ATTACH_in_valueattach1090 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000040L});
	public static final BitSet FOLLOW_KEY_VALUES_in_valueattach1094 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000080000000000L});
	public static final BitSet FOLLOW_identifierlist_in_valueattach1096 = new BitSet(new long[]{0x0000008000040400L,0x0000000000010400L});
	public static final BitSet FOLLOW_intblist_in_valueattach1099 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_ATTACH_in_nameattach1124 = new BitSet(new long[]{0x0800000000000000L});
	public static final BitSet FOLLOW_KEY_NAMES_in_nameattach1128 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000080000000000L});
	public static final BitSet FOLLOW_identifierlist_in_nameattach1132 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000080000200000L});
	public static final BitSet FOLLOW_stringoridentlist_in_nameattach1137 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_ATTACH_in_varattach1164 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000080L});
	public static final BitSet FOLLOW_KEY_VARIABLES_in_varattach1168 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000080000000000L});
	public static final BitSet FOLLOW_identifierlist_in_varattach1172 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000080000000000L});
	public static final BitSet FOLLOW_identifierlist_in_varattach1177 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LBRACKET_in_identifierlist1203 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL,0x0000000000000000L,0x0000080000000000L});
	public static final BitSet FOLLOW_id_or_wild_in_identifierlist1205 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL,0x0000000000000000L,0x0000080000800000L});
	public static final BitSet FOLLOW_RBRACKET_in_identifierlist1208 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_id_or_wild_in_identifierlist1223 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LBRACKET_in_stringoridentlist1244 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL,0x0000000000000000L,0x0000080000200000L});
	public static final BitSet FOLLOW_stringorident_in_stringoridentlist1246 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL,0x0000000000000000L,0x0000080000A00000L});
	public static final BitSet FOLLOW_RBRACKET_in_stringoridentlist1249 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_stringorident_in_stringoridentlist1264 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_id_or_wild_in_stringorident1284 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_qstring_in_stringorident1289 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LBRACKET_in_intblist1301 = new BitSet(new long[]{0x0000008000040400L,0x0000000000010000L,0x0000000000000000L,0x0000080000000000L});
	public static final BitSet FOLLOW_intbpart_in_intblist1303 = new BitSet(new long[]{0x0000008000040400L,0x0000000000010000L,0x0000000000000000L,0x0000080000800000L});
	public static final BitSet FOLLOW_RBRACKET_in_intblist1306 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_neginteger_in_intblist1321 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_neginteger_in_intbpart1341 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_UNDERSCORE_in_intbpart1348 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_neginteger1364 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_neginteger1371 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_neginteger1373 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_macrodef_in_constructorlike1393 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_withblock_in_constructorlike1398 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_constructor_in_constructorlike1403 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_MACRO_in_macrodef1416 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_macrodef1418 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_LPAREN_in_macrodef1422 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_arguments_in_macrodef1424 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_RPAREN_in_macrodef1427 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000200L});
	public static final BitSet FOLLOW_semanticbody_in_macrodef1429 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_oplist_in_arguments1454 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_oplist1484 = new BitSet(new long[]{0x0000000000010002L});
	public static final BitSet FOLLOW_COMMA_in_oplist1487 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_oplist1490 = new BitSet(new long[]{0x0000000000010002L});
	public static final BitSet FOLLOW_RES_WITH_in_withblock1505 = new BitSet(new long[]{0xFFFFFF0000008000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_id_or_nil_in_withblock1507 = new BitSet(new long[]{0x0000000000008000L});
	public static final BitSet FOLLOW_COLON_in_withblock1509 = new BitSet(new long[]{0xFFFFFF0000200000L,0x00000000000087FFL});
	public static final BitSet FOLLOW_bitpat_or_nil_in_withblock1511 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000600L});
	public static final BitSet FOLLOW_contextblock_in_withblock1513 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000200L});
	public static final BitSet FOLLOW_LBRACE_in_withblock1515 = new BitSet(new long[]{0xFFFFFF0000008000L,0x00000000000001FFL,0x0000000000000000L,0x0000000004400000L});
	public static final BitSet FOLLOW_constructorlikelist_in_withblock1517 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000400000L});
	public static final BitSet FOLLOW_RBRACE_in_withblock1519 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_id_or_nil1548 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_bitpattern_in_bitpat_or_nil1568 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_definition_in_def_or_conslike1588 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_constructorlike_in_def_or_conslike1593 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_def_or_conslike_in_constructorlikelist1604 = new BitSet(new long[]{0xFFFFFF0000008002L,0x00000000000001FFL,0x0000000000000000L,0x0000000004000000L});
	public static final BitSet FOLLOW_ctorstart_in_constructor1626 = new BitSet(new long[]{0xFFFFFF0000200000L,0x00000000000081FFL});
	public static final BitSet FOLLOW_bitpattern_in_constructor1628 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000620L});
	public static final BitSet FOLLOW_contextblock_in_constructor1630 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000220L});
	public static final BitSet FOLLOW_ctorsemantic_in_constructor1632 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_semanticbody_in_ctorsemantic1657 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_UNIMPL_in_ctorsemantic1672 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_in_bitpattern1693 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_ctorstart1712 = new BitSet(new long[]{0x0000000000008000L});
	public static final BitSet FOLLOW_display_in_ctorstart1714 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_display_in_ctorstart1729 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LBRACKET_in_contextblock1750 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL,0x0000000000000000L,0x0000000000800000L});
	public static final BitSet FOLLOW_ctxstmts_in_contextblock1752 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000800000L});
	public static final BitSet FOLLOW_RBRACKET_in_contextblock1754 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ctxstmt_in_ctxstmts1783 = new BitSet(new long[]{0xFFFFFF0000000002L,0x00000000000001FFL});
	public static final BitSet FOLLOW_ctxassign_in_ctxstmt1795 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_SEMI_in_ctxstmt1797 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pfuncall_in_ctxstmt1803 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_SEMI_in_ctxstmt1805 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ctxlval_in_ctxassign1817 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_ctxassign1821 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression_in_ctxassign1823 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_ctxlval1845 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_apply_in_pfuncall1856 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_or_in_pequation1867 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_seq_in_pequation_or1878 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000000000020000L});
	public static final BitSet FOLLOW_pequation_or_op_in_pequation_or1882 = new BitSet(new long[]{0xFFFFFF0000200000L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pequation_seq_in_pequation_or1885 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000000000020000L});
	public static final BitSet FOLLOW_PIPE_in_pequation_or_op1901 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_and_in_pequation_seq1919 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_pequation_seq_op_in_pequation_seq1923 = new BitSet(new long[]{0xFFFFFF0000200000L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pequation_and_in_pequation_seq1926 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000000040000000L});
	public static final BitSet FOLLOW_SEMI_in_pequation_seq_op1942 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_ellipsis_in_pequation_and1960 = new BitSet(new long[]{0x0000000000000042L});
	public static final BitSet FOLLOW_pequation_and_op_in_pequation_and1964 = new BitSet(new long[]{0xFFFFFF0000200000L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pequation_ellipsis_in_pequation_and1967 = new BitSet(new long[]{0x0000000000000042L});
	public static final BitSet FOLLOW_AMPERSAND_in_pequation_and_op1983 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ELLIPSIS_in_pequation_ellipsis2003 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pequation_ellipsis_right_in_pequation_ellipsis2005 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_ellipsis_right_in_pequation_ellipsis2019 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_atomic_in_pequation_ellipsis_right2037 = new BitSet(new long[]{0x0000000000200000L});
	public static final BitSet FOLLOW_ELLIPSIS_in_pequation_ellipsis_right2041 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_atomic_in_pequation_ellipsis_right2055 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_constraint_in_pequation_atomic2067 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_pequation_atomic2074 = new BitSet(new long[]{0xFFFFFF0000200000L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pequation_in_pequation_atomic2076 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_RPAREN_in_pequation_atomic2078 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_constraint2098 = new BitSet(new long[]{0x0000003000000082L,0x0000000000023000L});
	public static final BitSet FOLLOW_constraint_op_in_constraint2101 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression2_in_constraint2104 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ASSIGN_in_constraint_op2119 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_NOTEQUAL_in_constraint_op2133 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LESS_in_constraint_op2147 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LESSEQUAL_in_constraint_op2161 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_GREAT_in_constraint_op2175 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_GREATEQUAL_in_constraint_op2189 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_or_in_pexpression2207 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_xor_in_pexpression_or2218 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000002000020000L});
	public static final BitSet FOLLOW_pexpression_or_op_in_pexpression_or2221 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression_xor_in_pexpression_or2224 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000002000020000L});
	public static final BitSet FOLLOW_PIPE_in_pexpression_or_op2239 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SPEC_OR_in_pexpression_or_op2253 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_and_in_pexpression_xor2271 = new BitSet(new long[]{0x0000000000004002L,0x0000000000000000L,0x0000000000000000L,0x0000004000000000L});
	public static final BitSet FOLLOW_pexpression_xor_op_in_pexpression_xor2274 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression_and_in_pexpression_xor2277 = new BitSet(new long[]{0x0000000000004002L,0x0000000000000000L,0x0000000000000000L,0x0000004000000000L});
	public static final BitSet FOLLOW_CARET_in_pexpression_xor_op2292 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SPEC_XOR_in_pexpression_xor_op2306 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_shift_in_pexpression_and2324 = new BitSet(new long[]{0x0000000000000042L,0x0000000000000000L,0x0000000000000000L,0x0000001000000000L});
	public static final BitSet FOLLOW_pexpression_and_op_in_pexpression_and2327 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression_shift_in_pexpression_and2330 = new BitSet(new long[]{0x0000000000000042L,0x0000000000000000L,0x0000000000000000L,0x0000001000000000L});
	public static final BitSet FOLLOW_AMPERSAND_in_pexpression_and_op2345 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SPEC_AND_in_pexpression_and_op2359 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_add_in_pexpression_shift2377 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000800L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_pexpression_shift_op_in_pexpression_shift2380 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression_add_in_pexpression_shift2383 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000800L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_LEFT_in_pexpression_shift_op2398 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_RIGHT_in_pexpression_shift_op2412 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_mult_in_pexpression_add2430 = new BitSet(new long[]{0x0000000000000002L,0x0000000000010000L,0x0000000000000000L,0x0000000000040000L});
	public static final BitSet FOLLOW_pexpression_add_op_in_pexpression_add2433 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression_mult_in_pexpression_add2436 = new BitSet(new long[]{0x0000000000000002L,0x0000000000010000L,0x0000000000000000L,0x0000000000040000L});
	public static final BitSet FOLLOW_PLUS_in_pexpression_add_op2451 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_pexpression_add_op2465 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_unary_in_pexpression_mult2483 = new BitSet(new long[]{0x0000000000000102L,0x0000000000000000L,0x0000000000000000L,0x0000000200000000L});
	public static final BitSet FOLLOW_pexpression_mult_op_in_pexpression_mult2486 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression_unary_in_pexpression_mult2489 = new BitSet(new long[]{0x0000000000000102L,0x0000000000000000L,0x0000000000000000L,0x0000000200000000L});
	public static final BitSet FOLLOW_ASTERISK_in_pexpression_mult_op2504 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SLASH_in_pexpression_mult_op2518 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_unary_op_in_pexpression_unary2536 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pexpression_term_in_pexpression_unary2539 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_func_in_pexpression_unary2544 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_pexpression_unary_op2557 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_TILDE_in_pexpression_unary_op2571 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_apply_in_pexpression_func2589 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_term_in_pexpression_func2594 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_pexpression_apply2605 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_pexpression_operands_in_pexpression_apply2607 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_pexpression_operands2629 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020010000000L});
	public static final BitSet FOLLOW_pexpression_in_pexpression_operands2633 = new BitSet(new long[]{0x0000000000010000L,0x0000000000000000L,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_COMMA_in_pexpression_operands2636 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression_in_pexpression_operands2639 = new BitSet(new long[]{0x0000000000010000L,0x0000000000000000L,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_RPAREN_in_pexpression_operands2646 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_pexpression_term2658 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_pexpression_term2663 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_pexpression_term2670 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression_in_pexpression_term2672 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_RPAREN_in_pexpression_term2674 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_or_in_pexpression22694 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_xor_in_pexpression2_or2705 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000002000000000L});
	public static final BitSet FOLLOW_pexpression2_or_op_in_pexpression2_or2708 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression2_xor_in_pexpression2_or2711 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000002000000000L});
	public static final BitSet FOLLOW_SPEC_OR_in_pexpression2_or_op2726 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_and_in_pexpression2_xor2744 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000004000000000L});
	public static final BitSet FOLLOW_pexpression2_xor_op_in_pexpression2_xor2747 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression2_and_in_pexpression2_xor2750 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000004000000000L});
	public static final BitSet FOLLOW_SPEC_XOR_in_pexpression2_xor_op2765 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_shift_in_pexpression2_and2783 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000001000000000L});
	public static final BitSet FOLLOW_pexpression2_and_op_in_pexpression2_and2786 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression2_shift_in_pexpression2_and2789 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000001000000000L});
	public static final BitSet FOLLOW_SPEC_AND_in_pexpression2_and_op2804 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_add_in_pexpression2_shift2822 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000800L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_pexpression2_shift_op_in_pexpression2_shift2825 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression2_add_in_pexpression2_shift2828 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000800L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_LEFT_in_pexpression2_shift_op2843 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_RIGHT_in_pexpression2_shift_op2857 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_mult_in_pexpression2_add2875 = new BitSet(new long[]{0x0000000000000002L,0x0000000000010000L,0x0000000000000000L,0x0000000000040000L});
	public static final BitSet FOLLOW_pexpression2_add_op_in_pexpression2_add2878 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression2_mult_in_pexpression2_add2881 = new BitSet(new long[]{0x0000000000000002L,0x0000000000010000L,0x0000000000000000L,0x0000000000040000L});
	public static final BitSet FOLLOW_PLUS_in_pexpression2_add_op2896 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_pexpression2_add_op2910 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_unary_in_pexpression2_mult2928 = new BitSet(new long[]{0x0000000000000102L,0x0000000000000000L,0x0000000000000000L,0x0000000200000000L});
	public static final BitSet FOLLOW_pexpression2_mult_op_in_pexpression2_mult2931 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression2_unary_in_pexpression2_mult2934 = new BitSet(new long[]{0x0000000000000102L,0x0000000000000000L,0x0000000000000000L,0x0000000200000000L});
	public static final BitSet FOLLOW_ASTERISK_in_pexpression2_mult_op2949 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SLASH_in_pexpression2_mult_op2963 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_unary_op_in_pexpression2_unary2981 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pexpression2_term_in_pexpression2_unary2984 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_func_in_pexpression2_unary2989 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_pexpression2_unary_op3002 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_TILDE_in_pexpression2_unary_op3016 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_apply_in_pexpression2_func3034 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_term_in_pexpression2_func3039 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_pexpression2_apply3050 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_pexpression2_operands_in_pexpression2_apply3052 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_pexpression2_operands3074 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020010000000L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression2_operands3078 = new BitSet(new long[]{0x0000000000010000L,0x0000000000000000L,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_COMMA_in_pexpression2_operands3081 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression2_operands3084 = new BitSet(new long[]{0x0000000000010000L,0x0000000000000000L,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_RPAREN_in_pexpression2_operands3091 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_pexpression2_term3103 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_pexpression2_term3108 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_pexpression2_term3115 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression2_term3117 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000010000000L});
	public static final BitSet FOLLOW_RPAREN_in_pexpression2_term3119 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_QSTRING_in_qstring3141 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_id_or_wild3161 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_wildcard_in_id_or_wild3166 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_UNDERSCORE_in_wildcard3179 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_strict_id_in_identifier3196 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_key_as_id_in_identifier3201 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_ALIGNMENT_in_key_as_id3214 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_ATTACH_in_key_as_id3230 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_BIG_in_key_as_id3247 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_BITRANGE_in_key_as_id3265 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_BUILD_in_key_as_id3282 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_CALL_in_key_as_id3299 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_CONTEXT_in_key_as_id3318 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_CROSSBUILD_in_key_as_id3335 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEC_in_key_as_id3351 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFAULT_in_key_as_id3370 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_key_as_id3387 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_ENDIAN_in_key_as_id3404 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_EXPORT_in_key_as_id3421 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_GOTO_in_key_as_id3438 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_HEX_in_key_as_id3456 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_LITTLE_in_key_as_id3474 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_LOCAL_in_key_as_id3491 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_MACRO_in_key_as_id3508 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_NAMES_in_key_as_id3525 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_NOFLOW_in_key_as_id3542 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_OFFSET_in_key_as_id3559 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_PCODEOP_in_key_as_id3576 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_RETURN_in_key_as_id3593 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_SIGNED_in_key_as_id3610 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_SIZE_in_key_as_id3627 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_SPACE_in_key_as_id3645 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_TOKEN_in_key_as_id3662 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_TYPE_in_key_as_id3679 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_UNIMPL_in_key_as_id3697 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_VALUES_in_key_as_id3714 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_VARIABLES_in_key_as_id3731 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_WORDSIZE_in_key_as_id3747 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_IDENTIFIER_in_strict_id3770 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_HEX_INT_in_integer3793 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_DEC_INT_in_integer3809 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_BIN_INT_in_integer3825 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_atomic_in_synpred1_SleighParser2031 = new BitSet(new long[]{0x0000000000200000L});
	public static final BitSet FOLLOW_ELLIPSIS_in_synpred1_SleighParser2033 = new BitSet(new long[]{0x0000000000000002L});
}
