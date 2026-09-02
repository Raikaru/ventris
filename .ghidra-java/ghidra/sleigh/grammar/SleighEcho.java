package ghidra.sleigh.grammar;
// $ANTLR 3.5.2 ghidra/sleigh/grammar/SleighEcho.g 2026-08-17 17:23:46

	import java.io.PrintStream;

	import org.antlr.runtime.*;
	import org.antlr.runtime.tree.*;


import org.antlr.runtime.*;
import org.antlr.runtime.tree.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

@SuppressWarnings("all")
public class SleighEcho extends TreeParser {
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
		"WS"
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
	public TreeParser[] getDelegates() {
		return new TreeParser[] {};
	}

	// delegators


	public SleighEcho(TreeNodeStream input) {
		this(input, new RecognizerSharedState());
	}
	public SleighEcho(TreeNodeStream input, RecognizerSharedState state) {
		super(input, state);
	}

	@Override public String[] getTokenNames() { return SleighEcho.tokenNames; }
	@Override public String getGrammarFileName() { return "ghidra/sleigh/grammar/SleighEcho.g"; }


		public PrintStream out = System.out;

		void ot(String s) {
		    out.print(s);
		}

		void out(String s) {
		    out.println(s);
		}



	// $ANTLR start "root"
	// ghidra/sleigh/grammar/SleighEcho.g:27:1: root : endiandef ( definition | constructorlike )* ;
	public final void root() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:28:2: ( endiandef ( definition | constructorlike )* )
			// ghidra/sleigh/grammar/SleighEcho.g:28:4: endiandef ( definition | constructorlike )*
			{
			pushFollow(FOLLOW_endiandef_in_root42);
			endiandef();
			state._fsp--;

			// ghidra/sleigh/grammar/SleighEcho.g:29:3: ( definition | constructorlike )*
			loop1:
			while (true) {
				int alt1=3;
				int LA1_0 = input.LA(1);
				if ( (LA1_0==OP_ALIGNMENT||LA1_0==OP_BITRANGES||LA1_0==OP_CONTEXT||LA1_0==OP_NAMES||LA1_0==OP_PCODEOP||LA1_0==OP_SPACE||(LA1_0 >= OP_TOKEN && LA1_0 <= OP_TOKEN_ENDIAN)||(LA1_0 >= OP_VALUES && LA1_0 <= OP_VARNODE)) ) {
					alt1=1;
				}
				else if ( (LA1_0==OP_CONSTRUCTOR||LA1_0==OP_MACRO) ) {
					alt1=2;
				}

				switch (alt1) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:29:5: definition
					{
					pushFollow(FOLLOW_definition_in_root48);
					definition();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:30:5: constructorlike
					{
					pushFollow(FOLLOW_constructorlike_in_root54);
					constructorlike();
					state._fsp--;

					}
					break;

				default :
					break loop1;
				}
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "root"



	// $ANTLR start "endiandef"
	// ghidra/sleigh/grammar/SleighEcho.g:34:1: endiandef : ^( OP_ENDIAN s= endian ) ;
	public final void endiandef() throws RecognitionException {
		TreeRuleReturnScope s =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:35:2: ( ^( OP_ENDIAN s= endian ) )
			// ghidra/sleigh/grammar/SleighEcho.g:35:4: ^( OP_ENDIAN s= endian )
			{
			match(input,OP_ENDIAN,FOLLOW_OP_ENDIAN_in_endiandef71); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_endian_in_endiandef75);
			s=endian();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("define endian=" + (s!=null?(input.getTokenStream().toString(input.getTreeAdaptor().getTokenStartIndex(s.start),input.getTreeAdaptor().getTokenStopIndex(s.start))):null) + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "endiandef"


	public static class endian_return extends TreeRuleReturnScope {
	};


	// $ANTLR start "endian"
	// ghidra/sleigh/grammar/SleighEcho.g:38:1: endian : ( OP_BIG | OP_LITTLE );
	public final SleighEcho.endian_return endian() throws RecognitionException {
		SleighEcho.endian_return retval = new SleighEcho.endian_return();
		retval.start = input.LT(1);

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:39:2: ( OP_BIG | OP_LITTLE )
			// ghidra/sleigh/grammar/SleighEcho.g:
			{
			if ( input.LA(1)==OP_BIG||input.LA(1)==OP_LITTLE ) {
				input.consume();
				state.errorRecovery=false;
			}
			else {
				MismatchedSetException mse = new MismatchedSetException(null,input);
				throw mse;
			}
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "endian"



	// $ANTLR start "definition"
	// ghidra/sleigh/grammar/SleighEcho.g:43:1: definition : ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach ) ;
	public final void definition() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:44:2: ( ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach ) )
			// ghidra/sleigh/grammar/SleighEcho.g:44:4: ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach )
			{
			// ghidra/sleigh/grammar/SleighEcho.g:44:4: ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach )
			int alt2=10;
			switch ( input.LA(1) ) {
			case OP_ALIGNMENT:
				{
				alt2=1;
				}
				break;
			case OP_TOKEN:
			case OP_TOKEN_ENDIAN:
				{
				alt2=2;
				}
				break;
			case OP_CONTEXT:
				{
				alt2=3;
				}
				break;
			case OP_SPACE:
				{
				alt2=4;
				}
				break;
			case OP_VARNODE:
				{
				alt2=5;
				}
				break;
			case OP_BITRANGES:
				{
				alt2=6;
				}
				break;
			case OP_PCODEOP:
				{
				alt2=7;
				}
				break;
			case OP_VALUES:
				{
				alt2=8;
				}
				break;
			case OP_NAMES:
				{
				alt2=9;
				}
				break;
			case OP_VARIABLES:
				{
				alt2=10;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 2, 0, input);
				throw nvae;
			}
			switch (alt2) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:44:5: aligndef
					{
					pushFollow(FOLLOW_aligndef_in_definition106);
					aligndef();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:45:4: tokendef
					{
					pushFollow(FOLLOW_tokendef_in_definition111);
					tokendef();
					state._fsp--;

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:46:4: contextdef
					{
					pushFollow(FOLLOW_contextdef_in_definition116);
					contextdef();
					state._fsp--;

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighEcho.g:47:4: spacedef
					{
					pushFollow(FOLLOW_spacedef_in_definition121);
					spacedef();
					state._fsp--;

					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighEcho.g:48:4: varnodedef
					{
					pushFollow(FOLLOW_varnodedef_in_definition126);
					varnodedef();
					state._fsp--;

					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighEcho.g:49:4: bitrangedef
					{
					pushFollow(FOLLOW_bitrangedef_in_definition131);
					bitrangedef();
					state._fsp--;

					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighEcho.g:50:4: pcodeopdef
					{
					pushFollow(FOLLOW_pcodeopdef_in_definition136);
					pcodeopdef();
					state._fsp--;

					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighEcho.g:51:4: valueattach
					{
					pushFollow(FOLLOW_valueattach_in_definition141);
					valueattach();
					state._fsp--;

					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighEcho.g:52:4: nameattach
					{
					pushFollow(FOLLOW_nameattach_in_definition146);
					nameattach();
					state._fsp--;

					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighEcho.g:53:4: varattach
					{
					pushFollow(FOLLOW_varattach_in_definition151);
					varattach();
					state._fsp--;

					}
					break;

			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "definition"



	// $ANTLR start "aligndef"
	// ghidra/sleigh/grammar/SleighEcho.g:57:1: aligndef : ^( OP_ALIGNMENT i= integer ) ;
	public final void aligndef() throws RecognitionException {
		String i =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:58:2: ( ^( OP_ALIGNMENT i= integer ) )
			// ghidra/sleigh/grammar/SleighEcho.g:58:4: ^( OP_ALIGNMENT i= integer )
			{
			match(input,OP_ALIGNMENT,FOLLOW_OP_ALIGNMENT_in_aligndef166); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_integer_in_aligndef170);
			i=integer();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("define alignment=" + i + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "aligndef"



	// $ANTLR start "tokendef"
	// ghidra/sleigh/grammar/SleighEcho.g:61:1: tokendef : ( ^( OP_TOKEN n= identifier i= integer fielddefs ) | ^( OP_TOKEN_ENDIAN n= identifier i= integer s= endian fielddefs ) );
	public final void tokendef() throws RecognitionException {
		String n =null;
		String i =null;
		TreeRuleReturnScope s =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:62:2: ( ^( OP_TOKEN n= identifier i= integer fielddefs ) | ^( OP_TOKEN_ENDIAN n= identifier i= integer s= endian fielddefs ) )
			int alt3=2;
			int LA3_0 = input.LA(1);
			if ( (LA3_0==OP_TOKEN) ) {
				alt3=1;
			}
			else if ( (LA3_0==OP_TOKEN_ENDIAN) ) {
				alt3=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 3, 0, input);
				throw nvae;
			}

			switch (alt3) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:62:4: ^( OP_TOKEN n= identifier i= integer fielddefs )
					{
					match(input,OP_TOKEN,FOLLOW_OP_TOKEN_in_tokendef185); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_identifier_in_tokendef189);
					n=identifier();
					state._fsp--;

					pushFollow(FOLLOW_integer_in_tokendef193);
					i=integer();
					state._fsp--;

					 out("define token " + n + "(" + i + ")"); 
					pushFollow(FOLLOW_fielddefs_in_tokendef197);
					fielddefs();
					state._fsp--;

					match(input, Token.UP, null); 

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:63:6: ^( OP_TOKEN_ENDIAN n= identifier i= integer s= endian fielddefs )
					{
					match(input,OP_TOKEN_ENDIAN,FOLLOW_OP_TOKEN_ENDIAN_in_tokendef206); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_identifier_in_tokendef210);
					n=identifier();
					state._fsp--;

					pushFollow(FOLLOW_integer_in_tokendef214);
					i=integer();
					state._fsp--;

					pushFollow(FOLLOW_endian_in_tokendef218);
					s=endian();
					state._fsp--;

					 out("define token endian" + n + "(" + i + ")"); 
					pushFollow(FOLLOW_fielddefs_in_tokendef222);
					fielddefs();
					state._fsp--;

					match(input, Token.UP, null); 

					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "tokendef"



	// $ANTLR start "fielddefs"
	// ghidra/sleigh/grammar/SleighEcho.g:66:1: fielddefs : ^( OP_FIELDDEFS ( fielddef )* ) ;
	public final void fielddefs() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:67:2: ( ^( OP_FIELDDEFS ( fielddef )* ) )
			// ghidra/sleigh/grammar/SleighEcho.g:67:4: ^( OP_FIELDDEFS ( fielddef )* )
			{
			match(input,OP_FIELDDEFS,FOLLOW_OP_FIELDDEFS_in_fielddefs235); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				// ghidra/sleigh/grammar/SleighEcho.g:67:19: ( fielddef )*
				loop4:
				while (true) {
					int alt4=2;
					int LA4_0 = input.LA(1);
					if ( (LA4_0==OP_FIELDDEF) ) {
						alt4=1;
					}

					switch (alt4) {
					case 1 :
						// ghidra/sleigh/grammar/SleighEcho.g:67:19: fielddef
						{
						pushFollow(FOLLOW_fielddef_in_fielddefs237);
						fielddef();
						state._fsp--;

						}
						break;

					default :
						break loop4;
					}
				}

				match(input, Token.UP, null); 
			}

			 out(";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "fielddefs"



	// $ANTLR start "fielddef"
	// ghidra/sleigh/grammar/SleighEcho.g:70:1: fielddef : ^( OP_FIELDDEF n= identifier s= integer e= integer f= fieldmods ) ;
	public final void fielddef() throws RecognitionException {
		String n =null;
		String s =null;
		String e =null;
		String f =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:71:2: ( ^( OP_FIELDDEF n= identifier s= integer e= integer f= fieldmods ) )
			// ghidra/sleigh/grammar/SleighEcho.g:71:4: ^( OP_FIELDDEF n= identifier s= integer e= integer f= fieldmods )
			{
			match(input,OP_FIELDDEF,FOLLOW_OP_FIELDDEF_in_fielddef253); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifier_in_fielddef257);
			n=identifier();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_fielddef261);
			s=integer();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_fielddef265);
			e=integer();
			state._fsp--;

			pushFollow(FOLLOW_fieldmods_in_fielddef269);
			f=fieldmods();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("  " + n + " = (" + s + "," + e + ")" + f); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "fielddef"



	// $ANTLR start "fieldmods"
	// ghidra/sleigh/grammar/SleighEcho.g:75:1: fieldmods returns [String value] : ( ^( OP_FIELD_MODS (n= fieldmod )+ ) | OP_NO_FIELD_MOD );
	public final String fieldmods() throws RecognitionException {
		String value = null;


		String n =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:76:5: ( ^( OP_FIELD_MODS (n= fieldmod )+ ) | OP_NO_FIELD_MOD )
			int alt6=2;
			int LA6_0 = input.LA(1);
			if ( (LA6_0==OP_FIELD_MODS) ) {
				alt6=1;
			}
			else if ( (LA6_0==OP_NO_FIELD_MOD) ) {
				alt6=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 6, 0, input);
				throw nvae;
			}

			switch (alt6) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:76:9: ^( OP_FIELD_MODS (n= fieldmod )+ )
					{
					match(input,OP_FIELD_MODS,FOLLOW_OP_FIELD_MODS_in_fieldmods294); 
					 value = ""; 
					match(input, Token.DOWN, null); 
					// ghidra/sleigh/grammar/SleighEcho.g:76:42: (n= fieldmod )+
					int cnt5=0;
					loop5:
					while (true) {
						int alt5=2;
						int LA5_0 = input.LA(1);
						if ( (LA5_0==OP_DEC||LA5_0==OP_HEX||LA5_0==OP_NOFLOW||LA5_0==OP_SIGNED) ) {
							alt5=1;
						}

						switch (alt5) {
						case 1 :
							// ghidra/sleigh/grammar/SleighEcho.g:76:43: n= fieldmod
							{
							pushFollow(FOLLOW_fieldmod_in_fieldmods301);
							n=fieldmod();
							state._fsp--;

							 value += " " + n; 
							}
							break;

						default :
							if ( cnt5 >= 1 ) break loop5;
							EarlyExitException eee = new EarlyExitException(5, input);
							throw eee;
						}
						cnt5++;
					}

					match(input, Token.UP, null); 

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:77:9: OP_NO_FIELD_MOD
					{
					match(input,OP_NO_FIELD_MOD,FOLLOW_OP_NO_FIELD_MOD_in_fieldmods318); 
					 value = ""; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "fieldmods"



	// $ANTLR start "fieldmod"
	// ghidra/sleigh/grammar/SleighEcho.g:80:1: fieldmod returns [String value] : ( OP_SIGNED | OP_NOFLOW | OP_HEX | OP_DEC );
	public final String fieldmod() throws RecognitionException {
		String value = null;


		try {
			// ghidra/sleigh/grammar/SleighEcho.g:81:5: ( OP_SIGNED | OP_NOFLOW | OP_HEX | OP_DEC )
			int alt7=4;
			switch ( input.LA(1) ) {
			case OP_SIGNED:
				{
				alt7=1;
				}
				break;
			case OP_NOFLOW:
				{
				alt7=2;
				}
				break;
			case OP_HEX:
				{
				alt7=3;
				}
				break;
			case OP_DEC:
				{
				alt7=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 7, 0, input);
				throw nvae;
			}
			switch (alt7) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:81:9: OP_SIGNED
					{
					match(input,OP_SIGNED,FOLLOW_OP_SIGNED_in_fieldmod343); 
					 value = "signed"; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:82:9: OP_NOFLOW
					{
					match(input,OP_NOFLOW,FOLLOW_OP_NOFLOW_in_fieldmod355); 
					 value = "noflow"; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:83:9: OP_HEX
					{
					match(input,OP_HEX,FOLLOW_OP_HEX_in_fieldmod367); 
					 value = "hex"; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighEcho.g:84:9: OP_DEC
					{
					match(input,OP_DEC,FOLLOW_OP_DEC_in_fieldmod379); 
					 value = "dec"; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "fieldmod"



	// $ANTLR start "contextdef"
	// ghidra/sleigh/grammar/SleighEcho.g:87:1: contextdef : ^( OP_CONTEXT n= identifier fielddefs ) ;
	public final void contextdef() throws RecognitionException {
		String n =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:88:2: ( ^( OP_CONTEXT n= identifier fielddefs ) )
			// ghidra/sleigh/grammar/SleighEcho.g:88:4: ^( OP_CONTEXT n= identifier fielddefs )
			{
			match(input,OP_CONTEXT,FOLLOW_OP_CONTEXT_in_contextdef396); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifier_in_contextdef400);
			n=identifier();
			state._fsp--;

			 out("define context " + n); 
			pushFollow(FOLLOW_fielddefs_in_contextdef404);
			fielddefs();
			state._fsp--;

			match(input, Token.UP, null); 

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "contextdef"



	// $ANTLR start "spacedef"
	// ghidra/sleigh/grammar/SleighEcho.g:91:1: spacedef : ^( OP_SPACE n= identifier s= spacemods ) ;
	public final void spacedef() throws RecognitionException {
		String n =null;
		String s =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:92:2: ( ^( OP_SPACE n= identifier s= spacemods ) )
			// ghidra/sleigh/grammar/SleighEcho.g:92:4: ^( OP_SPACE n= identifier s= spacemods )
			{
			match(input,OP_SPACE,FOLLOW_OP_SPACE_in_spacedef417); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifier_in_spacedef421);
			n=identifier();
			state._fsp--;

			pushFollow(FOLLOW_spacemods_in_spacedef425);
			s=spacemods();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("define space " + n + s + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "spacedef"



	// $ANTLR start "spacemods"
	// ghidra/sleigh/grammar/SleighEcho.g:95:1: spacemods returns [String value] : ^( OP_SPACEMODS (s= spacemod )* ) ;
	public final String spacemods() throws RecognitionException {
		String value = null;


		String s =null;

		 value = ""; 
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:97:2: ( ^( OP_SPACEMODS (s= spacemod )* ) )
			// ghidra/sleigh/grammar/SleighEcho.g:97:4: ^( OP_SPACEMODS (s= spacemod )* )
			{
			match(input,OP_SPACEMODS,FOLLOW_OP_SPACEMODS_in_spacemods449); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				// ghidra/sleigh/grammar/SleighEcho.g:97:19: (s= spacemod )*
				loop8:
				while (true) {
					int alt8=2;
					int LA8_0 = input.LA(1);
					if ( (LA8_0==OP_DEFAULT||LA8_0==OP_SIZE||LA8_0==OP_TYPE||LA8_0==OP_WORDSIZE) ) {
						alt8=1;
					}

					switch (alt8) {
					case 1 :
						// ghidra/sleigh/grammar/SleighEcho.g:97:20: s= spacemod
						{
						pushFollow(FOLLOW_spacemod_in_spacemods454);
						s=spacemod();
						state._fsp--;

						 value += " " + s; 
						}
						break;

					default :
						break loop8;
					}
				}

				match(input, Token.UP, null); 
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "spacemods"



	// $ANTLR start "spacemod"
	// ghidra/sleigh/grammar/SleighEcho.g:100:1: spacemod returns [String value] : (t= typemod |s= sizemod |w= wordsizemod | OP_DEFAULT );
	public final String spacemod() throws RecognitionException {
		String value = null;


		String t =null;
		String s =null;
		String w =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:101:2: (t= typemod |s= sizemod |w= wordsizemod | OP_DEFAULT )
			int alt9=4;
			switch ( input.LA(1) ) {
			case OP_TYPE:
				{
				alt9=1;
				}
				break;
			case OP_SIZE:
				{
				alt9=2;
				}
				break;
			case OP_WORDSIZE:
				{
				alt9=3;
				}
				break;
			case OP_DEFAULT:
				{
				alt9=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 9, 0, input);
				throw nvae;
			}
			switch (alt9) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:101:4: t= typemod
					{
					pushFollow(FOLLOW_typemod_in_spacemod476);
					t=typemod();
					state._fsp--;

					 value = t; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:102:4: s= sizemod
					{
					pushFollow(FOLLOW_sizemod_in_spacemod485);
					s=sizemod();
					state._fsp--;

					 value = s; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:103:4: w= wordsizemod
					{
					pushFollow(FOLLOW_wordsizemod_in_spacemod494);
					w=wordsizemod();
					state._fsp--;

					 value = w; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighEcho.g:104:4: OP_DEFAULT
					{
					match(input,OP_DEFAULT,FOLLOW_OP_DEFAULT_in_spacemod501); 
					 value = "default"; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "spacemod"



	// $ANTLR start "typemod"
	// ghidra/sleigh/grammar/SleighEcho.g:107:1: typemod returns [String value] : ^( OP_TYPE n= type ) ;
	public final String typemod() throws RecognitionException {
		String value = null;


		String n =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:108:2: ( ^( OP_TYPE n= type ) )
			// ghidra/sleigh/grammar/SleighEcho.g:108:4: ^( OP_TYPE n= type )
			{
			match(input,OP_TYPE,FOLLOW_OP_TYPE_in_typemod519); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_type_in_typemod523);
			n=type();
			state._fsp--;

			match(input, Token.UP, null); 

			 value = "type=" + n; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "typemod"



	// $ANTLR start "type"
	// ghidra/sleigh/grammar/SleighEcho.g:111:1: type returns [String value] : n= identifier ;
	public final String type() throws RecognitionException {
		String value = null;


		String n =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:112:2: (n= identifier )
			// ghidra/sleigh/grammar/SleighEcho.g:112:4: n= identifier
			{
			pushFollow(FOLLOW_identifier_in_type543);
			n=identifier();
			state._fsp--;

			 value = n; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "type"



	// $ANTLR start "sizemod"
	// ghidra/sleigh/grammar/SleighEcho.g:115:1: sizemod returns [String value] : ^( OP_SIZE i= integer ) ;
	public final String sizemod() throws RecognitionException {
		String value = null;


		String i =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:116:2: ( ^( OP_SIZE i= integer ) )
			// ghidra/sleigh/grammar/SleighEcho.g:116:4: ^( OP_SIZE i= integer )
			{
			match(input,OP_SIZE,FOLLOW_OP_SIZE_in_sizemod561); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_integer_in_sizemod565);
			i=integer();
			state._fsp--;

			match(input, Token.UP, null); 

			 value = "size=" + i; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "sizemod"



	// $ANTLR start "wordsizemod"
	// ghidra/sleigh/grammar/SleighEcho.g:119:1: wordsizemod returns [String value] : ^( OP_WORDSIZE i= integer ) ;
	public final String wordsizemod() throws RecognitionException {
		String value = null;


		String i =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:120:2: ( ^( OP_WORDSIZE i= integer ) )
			// ghidra/sleigh/grammar/SleighEcho.g:120:4: ^( OP_WORDSIZE i= integer )
			{
			match(input,OP_WORDSIZE,FOLLOW_OP_WORDSIZE_in_wordsizemod584); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_integer_in_wordsizemod588);
			i=integer();
			state._fsp--;

			match(input, Token.UP, null); 

			 value = "wordsize=" + i; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "wordsizemod"



	// $ANTLR start "varnodedef"
	// ghidra/sleigh/grammar/SleighEcho.g:123:1: varnodedef : ^( OP_VARNODE n= identifier offset= integer size= integer l= identifierlist ) ;
	public final void varnodedef() throws RecognitionException {
		String n =null;
		String offset =null;
		String size =null;
		String l =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:124:2: ( ^( OP_VARNODE n= identifier offset= integer size= integer l= identifierlist ) )
			// ghidra/sleigh/grammar/SleighEcho.g:124:4: ^( OP_VARNODE n= identifier offset= integer size= integer l= identifierlist )
			{
			match(input,OP_VARNODE,FOLLOW_OP_VARNODE_in_varnodedef603); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifier_in_varnodedef607);
			n=identifier();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_varnodedef611);
			offset=integer();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_varnodedef615);
			size=integer();
			state._fsp--;

			pushFollow(FOLLOW_identifierlist_in_varnodedef619);
			l=identifierlist();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("define " + n + " offset=" + offset + " size=" + size + " " + l + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "varnodedef"



	// $ANTLR start "identifierlist"
	// ghidra/sleigh/grammar/SleighEcho.g:127:1: identifierlist returns [String value] : ^( OP_IDENTIFIER_LIST (n= identifier )+ ) ;
	public final String identifierlist() throws RecognitionException {
		String value = null;


		String n =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:128:2: ( ^( OP_IDENTIFIER_LIST (n= identifier )+ ) )
			// ghidra/sleigh/grammar/SleighEcho.g:128:4: ^( OP_IDENTIFIER_LIST (n= identifier )+ )
			{
			match(input,OP_IDENTIFIER_LIST,FOLLOW_OP_IDENTIFIER_LIST_in_identifierlist638); 
			 value = "["; 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighEcho.g:128:43: (n= identifier )+
			int cnt10=0;
			loop10:
			while (true) {
				int alt10=2;
				int LA10_0 = input.LA(1);
				if ( (LA10_0==OP_IDENTIFIER||LA10_0==OP_WILDCARD) ) {
					alt10=1;
				}

				switch (alt10) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:128:44: n= identifier
					{
					pushFollow(FOLLOW_identifier_in_identifierlist645);
					n=identifier();
					state._fsp--;

					 value += " " + n; 
					}
					break;

				default :
					if ( cnt10 >= 1 ) break loop10;
					EarlyExitException eee = new EarlyExitException(10, input);
					throw eee;
				}
				cnt10++;
			}

			match(input, Token.UP, null); 

			 value += " ]"; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "identifierlist"



	// $ANTLR start "stringoridentlist"
	// ghidra/sleigh/grammar/SleighEcho.g:131:1: stringoridentlist returns [String value] : ^( OP_STRING_OR_IDENT_LIST (n= stringorident )+ ) ;
	public final String stringoridentlist() throws RecognitionException {
		String value = null;


		String n =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:132:2: ( ^( OP_STRING_OR_IDENT_LIST (n= stringorident )+ ) )
			// ghidra/sleigh/grammar/SleighEcho.g:132:4: ^( OP_STRING_OR_IDENT_LIST (n= stringorident )+ )
			{
			match(input,OP_STRING_OR_IDENT_LIST,FOLLOW_OP_STRING_OR_IDENT_LIST_in_stringoridentlist669); 
			 value = "["; 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighEcho.g:132:48: (n= stringorident )+
			int cnt11=0;
			loop11:
			while (true) {
				int alt11=2;
				int LA11_0 = input.LA(1);
				if ( (LA11_0==OP_IDENTIFIER||LA11_0==OP_QSTRING||LA11_0==OP_WILDCARD) ) {
					alt11=1;
				}

				switch (alt11) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:132:49: n= stringorident
					{
					pushFollow(FOLLOW_stringorident_in_stringoridentlist676);
					n=stringorident();
					state._fsp--;

					 value += " " + n; 
					}
					break;

				default :
					if ( cnt11 >= 1 ) break loop11;
					EarlyExitException eee = new EarlyExitException(11, input);
					throw eee;
				}
				cnt11++;
			}

			match(input, Token.UP, null); 

			 value += " ]"; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "stringoridentlist"



	// $ANTLR start "stringorident"
	// ghidra/sleigh/grammar/SleighEcho.g:135:1: stringorident returns [String value] : (n= identifier |s= qstring );
	public final String stringorident() throws RecognitionException {
		String value = null;


		String n =null;
		String s =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:136:2: (n= identifier |s= qstring )
			int alt12=2;
			int LA12_0 = input.LA(1);
			if ( (LA12_0==OP_IDENTIFIER||LA12_0==OP_WILDCARD) ) {
				alt12=1;
			}
			else if ( (LA12_0==OP_QSTRING) ) {
				alt12=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 12, 0, input);
				throw nvae;
			}

			switch (alt12) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:136:4: n= identifier
					{
					pushFollow(FOLLOW_identifier_in_stringorident701);
					n=identifier();
					state._fsp--;

					 value = n; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:137:4: s= qstring
					{
					pushFollow(FOLLOW_qstring_in_stringorident710);
					s=qstring();
					state._fsp--;

					 value = s; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "stringorident"



	// $ANTLR start "bitrangedef"
	// ghidra/sleigh/grammar/SleighEcho.g:140:1: bitrangedef : ^( OP_BITRANGES bitranges ) ;
	public final void bitrangedef() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:141:2: ( ^( OP_BITRANGES bitranges ) )
			// ghidra/sleigh/grammar/SleighEcho.g:141:4: ^( OP_BITRANGES bitranges )
			{
			match(input,OP_BITRANGES,FOLLOW_OP_BITRANGES_in_bitrangedef724); 
			 ot("define bitrange "); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_bitranges_in_bitrangedef728);
			bitranges();
			state._fsp--;

			match(input, Token.UP, null); 

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "bitrangedef"



	// $ANTLR start "bitranges"
	// ghidra/sleigh/grammar/SleighEcho.g:144:1: bitranges : (s= sbitrange )+ ;
	public final void bitranges() throws RecognitionException {
		String s =null;

		 String sp = ""; 
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:146:2: ( (s= sbitrange )+ )
			// ghidra/sleigh/grammar/SleighEcho.g:146:4: (s= sbitrange )+
			{
			// ghidra/sleigh/grammar/SleighEcho.g:146:4: (s= sbitrange )+
			int cnt13=0;
			loop13:
			while (true) {
				int alt13=2;
				int LA13_0 = input.LA(1);
				if ( (LA13_0==OP_BITRANGE) ) {
					alt13=1;
				}

				switch (alt13) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:146:5: s= sbitrange
					{
					pushFollow(FOLLOW_sbitrange_in_bitranges748);
					s=sbitrange();
					state._fsp--;

					 out(sp + s); sp = "  "; 
					}
					break;

				default :
					if ( cnt13 >= 1 ) break loop13;
					EarlyExitException eee = new EarlyExitException(13, input);
					throw eee;
				}
				cnt13++;
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "bitranges"



	// $ANTLR start "sbitrange"
	// ghidra/sleigh/grammar/SleighEcho.g:149:1: sbitrange returns [String value] : ^( OP_BITRANGE a= identifier b= identifier i= integer j= integer ) ;
	public final String sbitrange() throws RecognitionException {
		String value = null;


		String a =null;
		String b =null;
		String i =null;
		String j =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:150:2: ( ^( OP_BITRANGE a= identifier b= identifier i= integer j= integer ) )
			// ghidra/sleigh/grammar/SleighEcho.g:150:5: ^( OP_BITRANGE a= identifier b= identifier i= integer j= integer )
			{
			match(input,OP_BITRANGE,FOLLOW_OP_BITRANGE_in_sbitrange769); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifier_in_sbitrange773);
			a=identifier();
			state._fsp--;

			pushFollow(FOLLOW_identifier_in_sbitrange777);
			b=identifier();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_sbitrange781);
			i=integer();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_sbitrange785);
			j=integer();
			state._fsp--;

			match(input, Token.UP, null); 

			 value = a + " = " + b + " [" + i + "," + j + "]"; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "sbitrange"



	// $ANTLR start "pcodeopdef"
	// ghidra/sleigh/grammar/SleighEcho.g:153:1: pcodeopdef : ^( OP_PCODEOP l= identifierlist ) ;
	public final void pcodeopdef() throws RecognitionException {
		String l =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:154:2: ( ^( OP_PCODEOP l= identifierlist ) )
			// ghidra/sleigh/grammar/SleighEcho.g:154:4: ^( OP_PCODEOP l= identifierlist )
			{
			match(input,OP_PCODEOP,FOLLOW_OP_PCODEOP_in_pcodeopdef800); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifierlist_in_pcodeopdef804);
			l=identifierlist();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("define pcodeop " + l + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "pcodeopdef"



	// $ANTLR start "valueattach"
	// ghidra/sleigh/grammar/SleighEcho.g:157:1: valueattach : ^( OP_VALUES a= identifierlist b= intblist ) ;
	public final void valueattach() throws RecognitionException {
		String a =null;
		String b =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:158:2: ( ^( OP_VALUES a= identifierlist b= intblist ) )
			// ghidra/sleigh/grammar/SleighEcho.g:158:4: ^( OP_VALUES a= identifierlist b= intblist )
			{
			match(input,OP_VALUES,FOLLOW_OP_VALUES_in_valueattach819); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifierlist_in_valueattach823);
			a=identifierlist();
			state._fsp--;

			pushFollow(FOLLOW_intblist_in_valueattach827);
			b=intblist();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("attach values " + a + " " + b + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "valueattach"



	// $ANTLR start "intblist"
	// ghidra/sleigh/grammar/SleighEcho.g:161:1: intblist returns [String value] : ^( OP_INTBLIST (n= intbpart )+ ) ;
	public final String intblist() throws RecognitionException {
		String value = null;


		String n =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:162:2: ( ^( OP_INTBLIST (n= intbpart )+ ) )
			// ghidra/sleigh/grammar/SleighEcho.g:162:4: ^( OP_INTBLIST (n= intbpart )+ )
			{
			match(input,OP_INTBLIST,FOLLOW_OP_INTBLIST_in_intblist846); 
			 value = "["; 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighEcho.g:162:36: (n= intbpart )+
			int cnt14=0;
			loop14:
			while (true) {
				int alt14=2;
				int LA14_0 = input.LA(1);
				if ( (LA14_0==OP_BIN_CONSTANT||LA14_0==OP_DEC_CONSTANT||LA14_0==OP_HEX_CONSTANT||LA14_0==OP_NEGATE||LA14_0==OP_WILDCARD) ) {
					alt14=1;
				}

				switch (alt14) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:162:37: n= intbpart
					{
					pushFollow(FOLLOW_intbpart_in_intblist853);
					n=intbpart();
					state._fsp--;

					 value += " " + n; 
					}
					break;

				default :
					if ( cnt14 >= 1 ) break loop14;
					EarlyExitException eee = new EarlyExitException(14, input);
					throw eee;
				}
				cnt14++;
			}

			match(input, Token.UP, null); 

			 value += " ]"; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "intblist"



	// $ANTLR start "intbpart"
	// ghidra/sleigh/grammar/SleighEcho.g:165:1: intbpart returns [String value] : ( OP_WILDCARD | ^( OP_NEGATE i= integer ) |i= integer );
	public final String intbpart() throws RecognitionException {
		String value = null;


		String i =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:166:2: ( OP_WILDCARD | ^( OP_NEGATE i= integer ) |i= integer )
			int alt15=3;
			switch ( input.LA(1) ) {
			case OP_WILDCARD:
				{
				alt15=1;
				}
				break;
			case OP_NEGATE:
				{
				alt15=2;
				}
				break;
			case OP_BIN_CONSTANT:
			case OP_DEC_CONSTANT:
			case OP_HEX_CONSTANT:
				{
				alt15=3;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 15, 0, input);
				throw nvae;
			}
			switch (alt15) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:166:4: OP_WILDCARD
					{
					match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_intbpart876); 
					 value = "_"; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:167:4: ^( OP_NEGATE i= integer )
					{
					match(input,OP_NEGATE,FOLLOW_OP_NEGATE_in_intbpart884); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_intbpart888);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "-" + i; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:168:4: i= integer
					{
					pushFollow(FOLLOW_integer_in_intbpart898);
					i=integer();
					state._fsp--;

					 value = i; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "intbpart"



	// $ANTLR start "nameattach"
	// ghidra/sleigh/grammar/SleighEcho.g:171:1: nameattach : ^( OP_NAMES a= identifierlist b= stringoridentlist ) ;
	public final void nameattach() throws RecognitionException {
		String a =null;
		String b =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:172:2: ( ^( OP_NAMES a= identifierlist b= stringoridentlist ) )
			// ghidra/sleigh/grammar/SleighEcho.g:172:4: ^( OP_NAMES a= identifierlist b= stringoridentlist )
			{
			match(input,OP_NAMES,FOLLOW_OP_NAMES_in_nameattach912); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifierlist_in_nameattach916);
			a=identifierlist();
			state._fsp--;

			pushFollow(FOLLOW_stringoridentlist_in_nameattach920);
			b=stringoridentlist();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("attach names " + a + " " + b + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "nameattach"



	// $ANTLR start "varattach"
	// ghidra/sleigh/grammar/SleighEcho.g:175:1: varattach : ^( OP_VARIABLES a= identifierlist b= identifierlist ) ;
	public final void varattach() throws RecognitionException {
		String a =null;
		String b =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:176:2: ( ^( OP_VARIABLES a= identifierlist b= identifierlist ) )
			// ghidra/sleigh/grammar/SleighEcho.g:176:4: ^( OP_VARIABLES a= identifierlist b= identifierlist )
			{
			match(input,OP_VARIABLES,FOLLOW_OP_VARIABLES_in_varattach935); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifierlist_in_varattach939);
			a=identifierlist();
			state._fsp--;

			pushFollow(FOLLOW_identifierlist_in_varattach943);
			b=identifierlist();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("attach variables " + a + " " + b + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "varattach"



	// $ANTLR start "constructorlike"
	// ghidra/sleigh/grammar/SleighEcho.g:179:1: constructorlike : ( macrodef | constructor );
	public final void constructorlike() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:180:2: ( macrodef | constructor )
			int alt16=2;
			int LA16_0 = input.LA(1);
			if ( (LA16_0==OP_MACRO) ) {
				alt16=1;
			}
			else if ( (LA16_0==OP_CONSTRUCTOR) ) {
				alt16=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 16, 0, input);
				throw nvae;
			}

			switch (alt16) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:180:4: macrodef
					{
					pushFollow(FOLLOW_macrodef_in_constructorlike957);
					macrodef();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:181:4: constructor
					{
					pushFollow(FOLLOW_constructor_in_constructorlike962);
					constructor();
					state._fsp--;

					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "constructorlike"



	// $ANTLR start "macrodef"
	// ghidra/sleigh/grammar/SleighEcho.g:184:1: macrodef : ^( OP_MACRO n= identifier a= arguments semantic ) ;
	public final void macrodef() throws RecognitionException {
		String n =null;
		String a =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:185:2: ( ^( OP_MACRO n= identifier a= arguments semantic ) )
			// ghidra/sleigh/grammar/SleighEcho.g:185:4: ^( OP_MACRO n= identifier a= arguments semantic )
			{
			match(input,OP_MACRO,FOLLOW_OP_MACRO_in_macrodef974); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifier_in_macrodef978);
			n=identifier();
			state._fsp--;

			pushFollow(FOLLOW_arguments_in_macrodef982);
			a=arguments();
			state._fsp--;

			 out("macro " + n + "(" + a + ")" ); 
			pushFollow(FOLLOW_semantic_in_macrodef986);
			semantic();
			state._fsp--;

			match(input, Token.UP, null); 

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "macrodef"



	// $ANTLR start "arguments"
	// ghidra/sleigh/grammar/SleighEcho.g:188:1: arguments returns [String value] : ( ^( OP_ARGUMENTS l= oplist ) | OP_EMPTY_LIST );
	public final String arguments() throws RecognitionException {
		String value = null;


		String l =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:189:2: ( ^( OP_ARGUMENTS l= oplist ) | OP_EMPTY_LIST )
			int alt17=2;
			int LA17_0 = input.LA(1);
			if ( (LA17_0==OP_ARGUMENTS) ) {
				alt17=1;
			}
			else if ( (LA17_0==OP_EMPTY_LIST) ) {
				alt17=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 17, 0, input);
				throw nvae;
			}

			switch (alt17) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:189:4: ^( OP_ARGUMENTS l= oplist )
					{
					match(input,OP_ARGUMENTS,FOLLOW_OP_ARGUMENTS_in_arguments1003); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_oplist_in_arguments1007);
					l=oplist();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:190:4: OP_EMPTY_LIST
					{
					match(input,OP_EMPTY_LIST,FOLLOW_OP_EMPTY_LIST_in_arguments1015); 
					 value = ""; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "arguments"



	// $ANTLR start "oplist"
	// ghidra/sleigh/grammar/SleighEcho.g:193:1: oplist returns [String value] : (n= identifier )+ ;
	public final String oplist() throws RecognitionException {
		String value = null;


		String n =null;

		 String comma = ""; value = ""; 
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:195:2: ( (n= identifier )+ )
			// ghidra/sleigh/grammar/SleighEcho.g:195:4: (n= identifier )+
			{
			// ghidra/sleigh/grammar/SleighEcho.g:195:4: (n= identifier )+
			int cnt18=0;
			loop18:
			while (true) {
				int alt18=2;
				int LA18_0 = input.LA(1);
				if ( (LA18_0==OP_IDENTIFIER||LA18_0==OP_WILDCARD) ) {
					alt18=1;
				}

				switch (alt18) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:195:5: n= identifier
					{
					pushFollow(FOLLOW_identifier_in_oplist1040);
					n=identifier();
					state._fsp--;

					 value += comma + n; comma = ","; 
					}
					break;

				default :
					if ( cnt18 >= 1 ) break loop18;
					EarlyExitException eee = new EarlyExitException(18, input);
					throw eee;
				}
				cnt18++;
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "oplist"



	// $ANTLR start "constructor"
	// ghidra/sleigh/grammar/SleighEcho.g:198:1: constructor : ^( OP_CONSTRUCTOR c= ctorstart b= bitpattern contextblock ctorsemantic ) ;
	public final void constructor() throws RecognitionException {
		String c =null;
		String b =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:199:2: ( ^( OP_CONSTRUCTOR c= ctorstart b= bitpattern contextblock ctorsemantic ) )
			// ghidra/sleigh/grammar/SleighEcho.g:199:4: ^( OP_CONSTRUCTOR c= ctorstart b= bitpattern contextblock ctorsemantic )
			{
			match(input,OP_CONSTRUCTOR,FOLLOW_OP_CONSTRUCTOR_in_constructor1056); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_ctorstart_in_constructor1060);
			c=ctorstart();
			state._fsp--;

			pushFollow(FOLLOW_bitpattern_in_constructor1064);
			b=bitpattern();
			state._fsp--;

			 ot(c + "is " + b + " "); 
			pushFollow(FOLLOW_contextblock_in_constructor1068);
			contextblock();
			state._fsp--;

			pushFollow(FOLLOW_ctorsemantic_in_constructor1070);
			ctorsemantic();
			state._fsp--;

			match(input, Token.UP, null); 

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "constructor"



	// $ANTLR start "ctorsemantic"
	// ghidra/sleigh/grammar/SleighEcho.g:202:1: ctorsemantic : ( ^( OP_PCODE semantic ) | ^( OP_PCODE OP_UNIMPL ) );
	public final void ctorsemantic() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:203:2: ( ^( OP_PCODE semantic ) | ^( OP_PCODE OP_UNIMPL ) )
			int alt19=2;
			int LA19_0 = input.LA(1);
			if ( (LA19_0==OP_PCODE) ) {
				int LA19_1 = input.LA(2);
				if ( (LA19_1==DOWN) ) {
					int LA19_2 = input.LA(3);
					if ( (LA19_2==OP_UNIMPL) ) {
						alt19=2;
					}
					else if ( (LA19_2==OP_SEMANTIC) ) {
						alt19=1;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 19, 2, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 19, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 19, 0, input);
				throw nvae;
			}

			switch (alt19) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:203:4: ^( OP_PCODE semantic )
					{
					match(input,OP_PCODE,FOLLOW_OP_PCODE_in_ctorsemantic1083); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_semantic_in_ctorsemantic1085);
					semantic();
					state._fsp--;

					match(input, Token.UP, null); 

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:204:4: ^( OP_PCODE OP_UNIMPL )
					{
					match(input,OP_PCODE,FOLLOW_OP_PCODE_in_ctorsemantic1092); 
					match(input, Token.DOWN, null); 
					match(input,OP_UNIMPL,FOLLOW_OP_UNIMPL_in_ctorsemantic1094); 
					match(input, Token.UP, null); 

					 out(" unimpl"); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "ctorsemantic"



	// $ANTLR start "bitpattern"
	// ghidra/sleigh/grammar/SleighEcho.g:207:1: bitpattern returns [String value] : ^( OP_BIT_PATTERN p= pequation ) ;
	public final String bitpattern() throws RecognitionException {
		String value = null;


		String p =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:208:2: ( ^( OP_BIT_PATTERN p= pequation ) )
			// ghidra/sleigh/grammar/SleighEcho.g:208:4: ^( OP_BIT_PATTERN p= pequation )
			{
			match(input,OP_BIT_PATTERN,FOLLOW_OP_BIT_PATTERN_in_bitpattern1113); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_pequation_in_bitpattern1117);
			p=pequation();
			state._fsp--;

			match(input, Token.UP, null); 

			 value = p; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "bitpattern"



	// $ANTLR start "ctorstart"
	// ghidra/sleigh/grammar/SleighEcho.g:211:1: ctorstart returns [String value] : ( ^( OP_SUBTABLE i= identifier d= display ) | ^( OP_TABLE d= display ) );
	public final String ctorstart() throws RecognitionException {
		String value = null;


		String i =null;
		String d =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:212:2: ( ^( OP_SUBTABLE i= identifier d= display ) | ^( OP_TABLE d= display ) )
			int alt20=2;
			int LA20_0 = input.LA(1);
			if ( (LA20_0==OP_SUBTABLE) ) {
				alt20=1;
			}
			else if ( (LA20_0==OP_TABLE) ) {
				alt20=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 20, 0, input);
				throw nvae;
			}

			switch (alt20) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:212:4: ^( OP_SUBTABLE i= identifier d= display )
					{
					match(input,OP_SUBTABLE,FOLLOW_OP_SUBTABLE_in_ctorstart1136); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_identifier_in_ctorstart1140);
					i=identifier();
					state._fsp--;

					pushFollow(FOLLOW_display_in_ctorstart1144);
					d=display();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = i + ":" + d; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:213:4: ^( OP_TABLE d= display )
					{
					match(input,OP_TABLE,FOLLOW_OP_TABLE_in_ctorstart1153); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_display_in_ctorstart1157);
					d=display();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = ":" + d; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "ctorstart"



	// $ANTLR start "display"
	// ghidra/sleigh/grammar/SleighEcho.g:216:1: display returns [String value] : ^( OP_DISPLAY p= pieces ) ;
	public final String display() throws RecognitionException {
		String value = null;


		String p =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:217:2: ( ^( OP_DISPLAY p= pieces ) )
			// ghidra/sleigh/grammar/SleighEcho.g:217:4: ^( OP_DISPLAY p= pieces )
			{
			match(input,OP_DISPLAY,FOLLOW_OP_DISPLAY_in_display1176); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				pushFollow(FOLLOW_pieces_in_display1180);
				p=pieces();
				state._fsp--;

				match(input, Token.UP, null); 
			}

			 value = p; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "display"



	// $ANTLR start "pieces"
	// ghidra/sleigh/grammar/SleighEcho.g:220:1: pieces returns [String value] : (p= printpiece )* ;
	public final String pieces() throws RecognitionException {
		String value = null;


		String p =null;

		 value = ""; 
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:222:2: ( (p= printpiece )* )
			// ghidra/sleigh/grammar/SleighEcho.g:222:4: (p= printpiece )*
			{
			// ghidra/sleigh/grammar/SleighEcho.g:222:4: (p= printpiece )*
			loop21:
			while (true) {
				int alt21=2;
				int LA21_0 = input.LA(1);
				if ( (LA21_0==OP_CONCATENATE||LA21_0==OP_IDENTIFIER||LA21_0==OP_QSTRING||LA21_0==OP_STRING||(LA21_0 >= OP_WHITESPACE && LA21_0 <= OP_WILDCARD)) ) {
					alt21=1;
				}

				switch (alt21) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:222:5: p= printpiece
					{
					pushFollow(FOLLOW_printpiece_in_pieces1206);
					p=printpiece();
					state._fsp--;

					 value += p; 
					}
					break;

				default :
					break loop21;
				}
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "pieces"



	// $ANTLR start "printpiece"
	// ghidra/sleigh/grammar/SleighEcho.g:225:1: printpiece returns [String value] : (i= identifier |w= whitespace | OP_CONCATENATE |s= string );
	public final String printpiece() throws RecognitionException {
		String value = null;


		String i =null;
		String w =null;
		String s =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:226:2: (i= identifier |w= whitespace | OP_CONCATENATE |s= string )
			int alt22=4;
			switch ( input.LA(1) ) {
			case OP_IDENTIFIER:
			case OP_WILDCARD:
				{
				alt22=1;
				}
				break;
			case OP_WHITESPACE:
				{
				alt22=2;
				}
				break;
			case OP_CONCATENATE:
				{
				alt22=3;
				}
				break;
			case OP_QSTRING:
			case OP_STRING:
				{
				alt22=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 22, 0, input);
				throw nvae;
			}
			switch (alt22) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:226:4: i= identifier
					{
					pushFollow(FOLLOW_identifier_in_printpiece1227);
					i=identifier();
					state._fsp--;

					 value = i; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:227:4: w= whitespace
					{
					pushFollow(FOLLOW_whitespace_in_printpiece1236);
					w=whitespace();
					state._fsp--;

					 value = w; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:228:4: OP_CONCATENATE
					{
					match(input,OP_CONCATENATE,FOLLOW_OP_CONCATENATE_in_printpiece1243); 
					 value = "^"; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighEcho.g:229:4: s= string
					{
					pushFollow(FOLLOW_string_in_printpiece1252);
					s=string();
					state._fsp--;

					 value = s; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "printpiece"



	// $ANTLR start "whitespace"
	// ghidra/sleigh/grammar/SleighEcho.g:232:1: whitespace returns [String value] : ^( OP_WHITESPACE s= . ) ;
	public final String whitespace() throws RecognitionException {
		String value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:233:2: ( ^( OP_WHITESPACE s= . ) )
			// ghidra/sleigh/grammar/SleighEcho.g:233:4: ^( OP_WHITESPACE s= . )
			{
			match(input,OP_WHITESPACE,FOLLOW_OP_WHITESPACE_in_whitespace1270); 
			match(input, Token.DOWN, null); 
			s=(CommonTree)input.LT(1);
			matchAny(input); 
			match(input, Token.UP, null); 

			 value = s.getText(); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "whitespace"



	// $ANTLR start "string"
	// ghidra/sleigh/grammar/SleighEcho.g:236:1: string returns [String value] : ( ^( OP_STRING s= . ) | ^( OP_QSTRING s= . ) );
	public final String string() throws RecognitionException {
		String value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:237:2: ( ^( OP_STRING s= . ) | ^( OP_QSTRING s= . ) )
			int alt23=2;
			int LA23_0 = input.LA(1);
			if ( (LA23_0==OP_STRING) ) {
				alt23=1;
			}
			else if ( (LA23_0==OP_QSTRING) ) {
				alt23=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 23, 0, input);
				throw nvae;
			}

			switch (alt23) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:237:4: ^( OP_STRING s= . )
					{
					match(input,OP_STRING,FOLLOW_OP_STRING_in_string1293); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = s.getText(); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:238:4: ^( OP_QSTRING s= . )
					{
					match(input,OP_QSTRING,FOLLOW_OP_QSTRING_in_string1306); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = "\"" + s.getText() + "\""; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "string"



	// $ANTLR start "pequation"
	// ghidra/sleigh/grammar/SleighEcho.g:241:1: pequation returns [String value] : ( ^( OP_BOOL_OR l= pequation r= pequation ) | ^( OP_SEQUENCE l= pequation r= pequation ) | ^( OP_BOOL_AND l= pequation r= pequation ) | ^( OP_ELLIPSIS l= pequation ) | ^( OP_ELLIPSIS_RIGHT l= pequation ) | ^( OP_EQUAL n= identifier x= pexpression2 ) | ^( OP_NOTEQUAL n= identifier x= pexpression2 ) | ^( OP_LESS n= identifier x= pexpression2 ) | ^( OP_LESSEQUAL n= identifier x= pexpression2 ) | ^( OP_GREAT n= identifier x= pexpression2 ) | ^( OP_GREATEQUAL n= identifier x= pexpression2 ) |n= identifier | ^( OP_PARENTHESIZED l= pequation ) );
	public final String pequation() throws RecognitionException {
		String value = null;


		String l =null;
		String r =null;
		String n =null;
		String x =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:242:2: ( ^( OP_BOOL_OR l= pequation r= pequation ) | ^( OP_SEQUENCE l= pequation r= pequation ) | ^( OP_BOOL_AND l= pequation r= pequation ) | ^( OP_ELLIPSIS l= pequation ) | ^( OP_ELLIPSIS_RIGHT l= pequation ) | ^( OP_EQUAL n= identifier x= pexpression2 ) | ^( OP_NOTEQUAL n= identifier x= pexpression2 ) | ^( OP_LESS n= identifier x= pexpression2 ) | ^( OP_LESSEQUAL n= identifier x= pexpression2 ) | ^( OP_GREAT n= identifier x= pexpression2 ) | ^( OP_GREATEQUAL n= identifier x= pexpression2 ) |n= identifier | ^( OP_PARENTHESIZED l= pequation ) )
			int alt24=13;
			switch ( input.LA(1) ) {
			case OP_BOOL_OR:
				{
				alt24=1;
				}
				break;
			case OP_SEQUENCE:
				{
				alt24=2;
				}
				break;
			case OP_BOOL_AND:
				{
				alt24=3;
				}
				break;
			case OP_ELLIPSIS:
				{
				alt24=4;
				}
				break;
			case OP_ELLIPSIS_RIGHT:
				{
				alt24=5;
				}
				break;
			case OP_EQUAL:
				{
				alt24=6;
				}
				break;
			case OP_NOTEQUAL:
				{
				alt24=7;
				}
				break;
			case OP_LESS:
				{
				alt24=8;
				}
				break;
			case OP_LESSEQUAL:
				{
				alt24=9;
				}
				break;
			case OP_GREAT:
				{
				alt24=10;
				}
				break;
			case OP_GREATEQUAL:
				{
				alt24=11;
				}
				break;
			case OP_IDENTIFIER:
			case OP_WILDCARD:
				{
				alt24=12;
				}
				break;
			case OP_PARENTHESIZED:
				{
				alt24=13;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 24, 0, input);
				throw nvae;
			}
			switch (alt24) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:242:4: ^( OP_BOOL_OR l= pequation r= pequation )
					{
					match(input,OP_BOOL_OR,FOLLOW_OP_BOOL_OR_in_pequation1329); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1333);
					l=pequation();
					state._fsp--;

					pushFollow(FOLLOW_pequation_in_pequation1337);
					r=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " | " + r; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:243:4: ^( OP_SEQUENCE l= pequation r= pequation )
					{
					match(input,OP_SEQUENCE,FOLLOW_OP_SEQUENCE_in_pequation1346); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1350);
					l=pequation();
					state._fsp--;

					pushFollow(FOLLOW_pequation_in_pequation1354);
					r=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " ; " + r; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:244:4: ^( OP_BOOL_AND l= pequation r= pequation )
					{
					match(input,OP_BOOL_AND,FOLLOW_OP_BOOL_AND_in_pequation1363); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1367);
					l=pequation();
					state._fsp--;

					pushFollow(FOLLOW_pequation_in_pequation1371);
					r=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " & " + r; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighEcho.g:246:4: ^( OP_ELLIPSIS l= pequation )
					{
					match(input,OP_ELLIPSIS,FOLLOW_OP_ELLIPSIS_in_pequation1381); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1385);
					l=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "... " + l; 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighEcho.g:247:4: ^( OP_ELLIPSIS_RIGHT l= pequation )
					{
					match(input,OP_ELLIPSIS_RIGHT,FOLLOW_OP_ELLIPSIS_RIGHT_in_pequation1394); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1398);
					l=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " ..."; 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighEcho.g:249:4: ^( OP_EQUAL n= identifier x= pexpression2 )
					{
					match(input,OP_EQUAL,FOLLOW_OP_EQUAL_in_pequation1408); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_identifier_in_pequation1412);
					n=identifier();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation1416);
					x=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = n + " = " + x; 
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighEcho.g:250:4: ^( OP_NOTEQUAL n= identifier x= pexpression2 )
					{
					match(input,OP_NOTEQUAL,FOLLOW_OP_NOTEQUAL_in_pequation1425); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_identifier_in_pequation1429);
					n=identifier();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation1433);
					x=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = n + " != " + x; 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighEcho.g:251:4: ^( OP_LESS n= identifier x= pexpression2 )
					{
					match(input,OP_LESS,FOLLOW_OP_LESS_in_pequation1442); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_identifier_in_pequation1446);
					n=identifier();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation1450);
					x=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = n + " < " + x; 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighEcho.g:252:4: ^( OP_LESSEQUAL n= identifier x= pexpression2 )
					{
					match(input,OP_LESSEQUAL,FOLLOW_OP_LESSEQUAL_in_pequation1459); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_identifier_in_pequation1463);
					n=identifier();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation1467);
					x=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = n + " <= " + x; 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighEcho.g:253:4: ^( OP_GREAT n= identifier x= pexpression2 )
					{
					match(input,OP_GREAT,FOLLOW_OP_GREAT_in_pequation1476); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_identifier_in_pequation1480);
					n=identifier();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation1484);
					x=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = n + " > " + x; 
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighEcho.g:254:4: ^( OP_GREATEQUAL n= identifier x= pexpression2 )
					{
					match(input,OP_GREATEQUAL,FOLLOW_OP_GREATEQUAL_in_pequation1493); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_identifier_in_pequation1497);
					n=identifier();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation1501);
					x=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = n + " >= " + x; 
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighEcho.g:256:4: n= identifier
					{
					pushFollow(FOLLOW_identifier_in_pequation1512);
					n=identifier();
					state._fsp--;

					 value = n; 
					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighEcho.g:257:4: ^( OP_PARENTHESIZED l= pequation )
					{
					match(input,OP_PARENTHESIZED,FOLLOW_OP_PARENTHESIZED_in_pequation1520); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1524);
					l=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "(" + l + ")"; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "pequation"



	// $ANTLR start "pexpression2"
	// ghidra/sleigh/grammar/SleighEcho.g:261:1: pexpression2 returns [String value] : ( ^( OP_OR l= pexpression2 r= pexpression2 ) | ^( OP_XOR l= pexpression2 r= pexpression2 ) | ^( OP_AND l= pexpression2 r= pexpression2 ) | ^( OP_LEFT l= pexpression2 r= pexpression2 ) | ^( OP_RIGHT l= pexpression2 r= pexpression2 ) | ^( OP_ADD l= pexpression2 r= pexpression2 ) | ^( OP_SUB l= pexpression2 r= pexpression2 ) | ^( OP_MULT l= pexpression2 r= pexpression2 ) | ^( OP_DIV l= pexpression2 r= pexpression2 ) | ^( OP_NEGATE l= pexpression2 ) | ^( OP_INVERT l= pexpression2 ) | ^( OP_APPLY n= identifier o= pexpression2_operands ) |n= identifier |i= integer | ^( OP_PARENTHESIZED l= pexpression2 ) );
	public final String pexpression2() throws RecognitionException {
		String value = null;


		String l =null;
		String r =null;
		String n =null;
		String o =null;
		String i =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:262:2: ( ^( OP_OR l= pexpression2 r= pexpression2 ) | ^( OP_XOR l= pexpression2 r= pexpression2 ) | ^( OP_AND l= pexpression2 r= pexpression2 ) | ^( OP_LEFT l= pexpression2 r= pexpression2 ) | ^( OP_RIGHT l= pexpression2 r= pexpression2 ) | ^( OP_ADD l= pexpression2 r= pexpression2 ) | ^( OP_SUB l= pexpression2 r= pexpression2 ) | ^( OP_MULT l= pexpression2 r= pexpression2 ) | ^( OP_DIV l= pexpression2 r= pexpression2 ) | ^( OP_NEGATE l= pexpression2 ) | ^( OP_INVERT l= pexpression2 ) | ^( OP_APPLY n= identifier o= pexpression2_operands ) |n= identifier |i= integer | ^( OP_PARENTHESIZED l= pexpression2 ) )
			int alt25=15;
			switch ( input.LA(1) ) {
			case OP_OR:
				{
				alt25=1;
				}
				break;
			case OP_XOR:
				{
				alt25=2;
				}
				break;
			case OP_AND:
				{
				alt25=3;
				}
				break;
			case OP_LEFT:
				{
				alt25=4;
				}
				break;
			case OP_RIGHT:
				{
				alt25=5;
				}
				break;
			case OP_ADD:
				{
				alt25=6;
				}
				break;
			case OP_SUB:
				{
				alt25=7;
				}
				break;
			case OP_MULT:
				{
				alt25=8;
				}
				break;
			case OP_DIV:
				{
				alt25=9;
				}
				break;
			case OP_NEGATE:
				{
				alt25=10;
				}
				break;
			case OP_INVERT:
				{
				alt25=11;
				}
				break;
			case OP_APPLY:
				{
				alt25=12;
				}
				break;
			case OP_IDENTIFIER:
			case OP_WILDCARD:
				{
				alt25=13;
				}
				break;
			case OP_BIN_CONSTANT:
			case OP_DEC_CONSTANT:
			case OP_HEX_CONSTANT:
				{
				alt25=14;
				}
				break;
			case OP_PARENTHESIZED:
				{
				alt25=15;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 25, 0, input);
				throw nvae;
			}
			switch (alt25) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:262:4: ^( OP_OR l= pexpression2 r= pexpression2 )
					{
					match(input,OP_OR,FOLLOW_OP_OR_in_pexpression21544); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression21548);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression21552);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " $or " + r; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:263:4: ^( OP_XOR l= pexpression2 r= pexpression2 )
					{
					match(input,OP_XOR,FOLLOW_OP_XOR_in_pexpression21561); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression21565);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression21569);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " $xor " + r; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:264:4: ^( OP_AND l= pexpression2 r= pexpression2 )
					{
					match(input,OP_AND,FOLLOW_OP_AND_in_pexpression21578); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression21582);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression21586);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " $and " + r; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighEcho.g:265:4: ^( OP_LEFT l= pexpression2 r= pexpression2 )
					{
					match(input,OP_LEFT,FOLLOW_OP_LEFT_in_pexpression21595); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression21599);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression21603);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " << " + r; 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighEcho.g:266:4: ^( OP_RIGHT l= pexpression2 r= pexpression2 )
					{
					match(input,OP_RIGHT,FOLLOW_OP_RIGHT_in_pexpression21612); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression21616);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression21620);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " >> " + r; 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighEcho.g:267:4: ^( OP_ADD l= pexpression2 r= pexpression2 )
					{
					match(input,OP_ADD,FOLLOW_OP_ADD_in_pexpression21629); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression21633);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression21637);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " + " + r; 
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighEcho.g:268:4: ^( OP_SUB l= pexpression2 r= pexpression2 )
					{
					match(input,OP_SUB,FOLLOW_OP_SUB_in_pexpression21646); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression21650);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression21654);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " - " + r; 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighEcho.g:269:4: ^( OP_MULT l= pexpression2 r= pexpression2 )
					{
					match(input,OP_MULT,FOLLOW_OP_MULT_in_pexpression21663); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression21667);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression21671);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " * " + r; 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighEcho.g:270:4: ^( OP_DIV l= pexpression2 r= pexpression2 )
					{
					match(input,OP_DIV,FOLLOW_OP_DIV_in_pexpression21680); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression21684);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression21688);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " / " + r; 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighEcho.g:272:4: ^( OP_NEGATE l= pexpression2 )
					{
					match(input,OP_NEGATE,FOLLOW_OP_NEGATE_in_pexpression21698); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression21702);
					l=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "-" + l; 
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighEcho.g:273:4: ^( OP_INVERT l= pexpression2 )
					{
					match(input,OP_INVERT,FOLLOW_OP_INVERT_in_pexpression21711); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression21715);
					l=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "~" + l; 
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighEcho.g:275:4: ^( OP_APPLY n= identifier o= pexpression2_operands )
					{
					match(input,OP_APPLY,FOLLOW_OP_APPLY_in_pexpression21725); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_identifier_in_pexpression21729);
					n=identifier();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_operands_in_pexpression21733);
					o=pexpression2_operands();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = n + "(" + o + ")"; 
					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighEcho.g:276:4: n= identifier
					{
					pushFollow(FOLLOW_identifier_in_pexpression21743);
					n=identifier();
					state._fsp--;

					 value = n; 
					}
					break;
				case 14 :
					// ghidra/sleigh/grammar/SleighEcho.g:277:4: i= integer
					{
					pushFollow(FOLLOW_integer_in_pexpression21752);
					i=integer();
					state._fsp--;

					 value = i; 
					}
					break;
				case 15 :
					// ghidra/sleigh/grammar/SleighEcho.g:278:4: ^( OP_PARENTHESIZED l= pexpression2 )
					{
					match(input,OP_PARENTHESIZED,FOLLOW_OP_PARENTHESIZED_in_pexpression21760); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression21764);
					l=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "(" + l + ")"; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "pexpression2"



	// $ANTLR start "pexpression2_operands"
	// ghidra/sleigh/grammar/SleighEcho.g:281:1: pexpression2_operands returns [String value] : (e= pexpression2 )* ;
	public final String pexpression2_operands() throws RecognitionException {
		String value = null;


		String e =null;

		 String comma = ""; value = ""; 
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:283:2: ( (e= pexpression2 )* )
			// ghidra/sleigh/grammar/SleighEcho.g:283:4: (e= pexpression2 )*
			{
			// ghidra/sleigh/grammar/SleighEcho.g:283:4: (e= pexpression2 )*
			loop26:
			while (true) {
				int alt26=2;
				int LA26_0 = input.LA(1);
				if ( (LA26_0==OP_ADD||(LA26_0 >= OP_AND && LA26_0 <= OP_APPLY)||LA26_0==OP_BIN_CONSTANT||LA26_0==OP_DEC_CONSTANT||LA26_0==OP_DIV||(LA26_0 >= OP_HEX_CONSTANT && LA26_0 <= OP_IDENTIFIER)||LA26_0==OP_INVERT||LA26_0==OP_LEFT||LA26_0==OP_MULT||LA26_0==OP_NEGATE||(LA26_0 >= OP_OR && LA26_0 <= OP_PARENTHESIZED)||LA26_0==OP_RIGHT||LA26_0==OP_SUB||LA26_0==OP_WILDCARD||LA26_0==OP_XOR) ) {
					alt26=1;
				}

				switch (alt26) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:283:5: e= pexpression2
					{
					pushFollow(FOLLOW_pexpression2_in_pexpression2_operands1790);
					e=pexpression2();
					state._fsp--;

					 value += comma + e; comma = ","; 
					}
					break;

				default :
					break loop26;
				}
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "pexpression2_operands"



	// $ANTLR start "contextblock"
	// ghidra/sleigh/grammar/SleighEcho.g:286:1: contextblock : ( ^( OP_CONTEXT_BLOCK statements ) | OP_NO_CONTEXT_BLOCK );
	public final void contextblock() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:287:2: ( ^( OP_CONTEXT_BLOCK statements ) | OP_NO_CONTEXT_BLOCK )
			int alt27=2;
			int LA27_0 = input.LA(1);
			if ( (LA27_0==OP_CONTEXT_BLOCK) ) {
				alt27=1;
			}
			else if ( (LA27_0==OP_NO_CONTEXT_BLOCK) ) {
				alt27=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 27, 0, input);
				throw nvae;
			}

			switch (alt27) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:287:4: ^( OP_CONTEXT_BLOCK statements )
					{
					match(input,OP_CONTEXT_BLOCK,FOLLOW_OP_CONTEXT_BLOCK_in_contextblock1806); 
					 ot("[ "); 
					if ( input.LA(1)==Token.DOWN ) {
						match(input, Token.DOWN, null); 
						pushFollow(FOLLOW_statements_in_contextblock1810);
						statements();
						state._fsp--;

						 ot(" ]"); 
						match(input, Token.UP, null); 
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:288:4: OP_NO_CONTEXT_BLOCK
					{
					match(input,OP_NO_CONTEXT_BLOCK,FOLLOW_OP_NO_CONTEXT_BLOCK_in_contextblock1818); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "contextblock"



	// $ANTLR start "semantic"
	// ghidra/sleigh/grammar/SleighEcho.g:291:1: semantic : ^( OP_SEMANTIC code_block ) ;
	public final void semantic() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:292:2: ( ^( OP_SEMANTIC code_block ) )
			// ghidra/sleigh/grammar/SleighEcho.g:292:4: ^( OP_SEMANTIC code_block )
			{
			match(input,OP_SEMANTIC,FOLLOW_OP_SEMANTIC_in_semantic1830); 
			 out("{"); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				pushFollow(FOLLOW_code_block_in_semantic1834);
				code_block();
				state._fsp--;

				 out("}"); 
				match(input, Token.UP, null); 
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "semantic"



	// $ANTLR start "code_block"
	// ghidra/sleigh/grammar/SleighEcho.g:295:1: code_block : ( statements | OP_NOP );
	public final void code_block() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:296:2: ( statements | OP_NOP )
			int alt28=2;
			int LA28_0 = input.LA(1);
			if ( (LA28_0==UP||LA28_0==OP_APPLY||LA28_0==OP_ASSIGN||(LA28_0 >= OP_BUILD && LA28_0 <= OP_CALL)||LA28_0==OP_CROSSBUILD||LA28_0==OP_EXPORT||LA28_0==OP_GOTO||LA28_0==OP_IF||LA28_0==OP_LABEL||LA28_0==OP_LOCAL||LA28_0==OP_RETURN||LA28_0==OP_SECTION_LABEL) ) {
				alt28=1;
			}
			else if ( (LA28_0==OP_NOP) ) {
				alt28=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 28, 0, input);
				throw nvae;
			}

			switch (alt28) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:296:4: statements
					{
					pushFollow(FOLLOW_statements_in_code_block1849);
					statements();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:297:4: OP_NOP
					{
					match(input,OP_NOP,FOLLOW_OP_NOP_in_code_block1854); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "code_block"



	// $ANTLR start "statements"
	// ghidra/sleigh/grammar/SleighEcho.g:300:1: statements : ( statement )* ;
	public final void statements() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:301:2: ( ( statement )* )
			// ghidra/sleigh/grammar/SleighEcho.g:301:4: ( statement )*
			{
			// ghidra/sleigh/grammar/SleighEcho.g:301:4: ( statement )*
			loop29:
			while (true) {
				int alt29=2;
				int LA29_0 = input.LA(1);
				if ( (LA29_0==OP_APPLY||LA29_0==OP_ASSIGN||(LA29_0 >= OP_BUILD && LA29_0 <= OP_CALL)||LA29_0==OP_CROSSBUILD||LA29_0==OP_EXPORT||LA29_0==OP_GOTO||LA29_0==OP_IF||LA29_0==OP_LABEL||LA29_0==OP_LOCAL||LA29_0==OP_RETURN||LA29_0==OP_SECTION_LABEL) ) {
					alt29=1;
				}

				switch (alt29) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:301:6: statement
					{
					 ot("  "); 
					pushFollow(FOLLOW_statement_in_statements1869);
					statement();
					state._fsp--;

					}
					break;

				default :
					break loop29;
				}
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "statements"



	// $ANTLR start "label"
	// ghidra/sleigh/grammar/SleighEcho.g:304:1: label returns [String value] : ^( OP_LABEL n= variable ) ;
	public final String label() throws RecognitionException {
		String value = null;


		String n =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:305:2: ( ^( OP_LABEL n= variable ) )
			// ghidra/sleigh/grammar/SleighEcho.g:305:4: ^( OP_LABEL n= variable )
			{
			match(input,OP_LABEL,FOLLOW_OP_LABEL_in_label1887); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_variable_in_label1891);
			n=variable();
			state._fsp--;

			match(input, Token.UP, null); 

			 value = "<" + n + ">"; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "label"



	// $ANTLR start "section_label"
	// ghidra/sleigh/grammar/SleighEcho.g:308:1: section_label returns [String value] : ^( OP_SECTION_LABEL n= variable ) ;
	public final String section_label() throws RecognitionException {
		String value = null;


		String n =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:309:2: ( ^( OP_SECTION_LABEL n= variable ) )
			// ghidra/sleigh/grammar/SleighEcho.g:309:4: ^( OP_SECTION_LABEL n= variable )
			{
			match(input,OP_SECTION_LABEL,FOLLOW_OP_SECTION_LABEL_in_section_label1910); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_variable_in_section_label1914);
			n=variable();
			state._fsp--;

			match(input, Token.UP, null); 

			 value = "<<" + n + ">>"; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "section_label"



	// $ANTLR start "statement"
	// ghidra/sleigh/grammar/SleighEcho.g:312:1: statement : ( assignment | declaration | funcall | build_stmt | crossbuild_stmt | goto_stmt | cond_stmt | call_stmt | export | return_stmt |l= label |s= section_label );
	public final void statement() throws RecognitionException {
		String l =null;
		String s =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:313:2: ( assignment | declaration | funcall | build_stmt | crossbuild_stmt | goto_stmt | cond_stmt | call_stmt | export | return_stmt |l= label |s= section_label )
			int alt30=12;
			switch ( input.LA(1) ) {
			case OP_ASSIGN:
				{
				alt30=1;
				}
				break;
			case OP_LOCAL:
				{
				int LA30_2 = input.LA(2);
				if ( (LA30_2==DOWN) ) {
					int LA30_13 = input.LA(3);
					if ( (LA30_13==OP_ASSIGN) ) {
						alt30=1;
					}
					else if ( (LA30_13==OP_IDENTIFIER||LA30_13==OP_WILDCARD) ) {
						alt30=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 30, 13, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

				}

				else {
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
			case OP_APPLY:
				{
				alt30=3;
				}
				break;
			case OP_BUILD:
				{
				alt30=4;
				}
				break;
			case OP_CROSSBUILD:
				{
				alt30=5;
				}
				break;
			case OP_GOTO:
				{
				alt30=6;
				}
				break;
			case OP_IF:
				{
				alt30=7;
				}
				break;
			case OP_CALL:
				{
				alt30=8;
				}
				break;
			case OP_EXPORT:
				{
				alt30=9;
				}
				break;
			case OP_RETURN:
				{
				alt30=10;
				}
				break;
			case OP_LABEL:
				{
				alt30=11;
				}
				break;
			case OP_SECTION_LABEL:
				{
				alt30=12;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 30, 0, input);
				throw nvae;
			}
			switch (alt30) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:313:4: assignment
					{
					pushFollow(FOLLOW_assignment_in_statement1928);
					assignment();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:314:4: declaration
					{
					pushFollow(FOLLOW_declaration_in_statement1933);
					declaration();
					state._fsp--;

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:315:4: funcall
					{
					pushFollow(FOLLOW_funcall_in_statement1938);
					funcall();
					state._fsp--;

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighEcho.g:316:4: build_stmt
					{
					pushFollow(FOLLOW_build_stmt_in_statement1943);
					build_stmt();
					state._fsp--;

					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighEcho.g:317:4: crossbuild_stmt
					{
					pushFollow(FOLLOW_crossbuild_stmt_in_statement1948);
					crossbuild_stmt();
					state._fsp--;

					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighEcho.g:318:4: goto_stmt
					{
					pushFollow(FOLLOW_goto_stmt_in_statement1953);
					goto_stmt();
					state._fsp--;

					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighEcho.g:319:4: cond_stmt
					{
					pushFollow(FOLLOW_cond_stmt_in_statement1958);
					cond_stmt();
					state._fsp--;

					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighEcho.g:320:4: call_stmt
					{
					pushFollow(FOLLOW_call_stmt_in_statement1963);
					call_stmt();
					state._fsp--;

					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighEcho.g:321:4: export
					{
					pushFollow(FOLLOW_export_in_statement1968);
					export();
					state._fsp--;

					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighEcho.g:322:4: return_stmt
					{
					pushFollow(FOLLOW_return_stmt_in_statement1973);
					return_stmt();
					state._fsp--;

					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighEcho.g:323:4: l= label
					{
					pushFollow(FOLLOW_label_in_statement1980);
					l=label();
					state._fsp--;

					 out(l); 
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighEcho.g:324:4: s= section_label
					{
					pushFollow(FOLLOW_section_label_in_statement1989);
					s=section_label();
					state._fsp--;

					 out(s); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "statement"



	// $ANTLR start "assignment"
	// ghidra/sleigh/grammar/SleighEcho.g:327:1: assignment : ( ^( OP_ASSIGN l= lvalue e= expr ) | ^( OP_LOCAL OP_ASSIGN l= lvalue e= expr ) );
	public final void assignment() throws RecognitionException {
		String l =null;
		String e =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:328:2: ( ^( OP_ASSIGN l= lvalue e= expr ) | ^( OP_LOCAL OP_ASSIGN l= lvalue e= expr ) )
			int alt31=2;
			int LA31_0 = input.LA(1);
			if ( (LA31_0==OP_ASSIGN) ) {
				alt31=1;
			}
			else if ( (LA31_0==OP_LOCAL) ) {
				alt31=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 31, 0, input);
				throw nvae;
			}

			switch (alt31) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:328:4: ^( OP_ASSIGN l= lvalue e= expr )
					{
					match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment2003); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_lvalue_in_assignment2007);
					l=lvalue();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_assignment2011);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 out(l + " = " + e + ";"); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:329:4: ^( OP_LOCAL OP_ASSIGN l= lvalue e= expr )
					{
					match(input,OP_LOCAL,FOLLOW_OP_LOCAL_in_assignment2020); 
					match(input, Token.DOWN, null); 
					match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment2022); 
					pushFollow(FOLLOW_lvalue_in_assignment2026);
					l=lvalue();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_assignment2030);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 out("local " + l + " = " + e + ";"); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "assignment"



	// $ANTLR start "declaration"
	// ghidra/sleigh/grammar/SleighEcho.g:332:1: declaration : ( ^( OP_LOCAL v= variable a= constant ) | ^( OP_LOCAL v= variable ) );
	public final void declaration() throws RecognitionException {
		String v =null;
		String a =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:333:2: ( ^( OP_LOCAL v= variable a= constant ) | ^( OP_LOCAL v= variable ) )
			int alt32=2;
			alt32 = dfa32.predict(input);
			switch (alt32) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:333:4: ^( OP_LOCAL v= variable a= constant )
					{
					match(input,OP_LOCAL,FOLLOW_OP_LOCAL_in_declaration2045); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_variable_in_declaration2049);
					v=variable();
					state._fsp--;

					pushFollow(FOLLOW_constant_in_declaration2053);
					a=constant();
					state._fsp--;

					match(input, Token.UP, null); 

					 out("local " + v + ":" + a + ";"); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:334:4: ^( OP_LOCAL v= variable )
					{
					match(input,OP_LOCAL,FOLLOW_OP_LOCAL_in_declaration2062); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_variable_in_declaration2066);
					v=variable();
					state._fsp--;

					match(input, Token.UP, null); 

					 out("local " + v + ";"); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "declaration"



	// $ANTLR start "lvalue"
	// ghidra/sleigh/grammar/SleighEcho.g:337:1: lvalue returns [String value] : (b= bitrange | ^( OP_DECLARATIVE_SIZE v= variable c= constant ) |v= variable |s= sizedstar );
	public final String lvalue() throws RecognitionException {
		String value = null;


		String b =null;
		String v =null;
		String c =null;
		String s =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:338:2: (b= bitrange | ^( OP_DECLARATIVE_SIZE v= variable c= constant ) |v= variable |s= sizedstar )
			int alt33=4;
			switch ( input.LA(1) ) {
			case OP_BITRANGE:
				{
				alt33=1;
				}
				break;
			case OP_DECLARATIVE_SIZE:
				{
				alt33=2;
				}
				break;
			case OP_IDENTIFIER:
			case OP_WILDCARD:
				{
				alt33=3;
				}
				break;
			case OP_DEREFERENCE:
				{
				alt33=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 33, 0, input);
				throw nvae;
			}
			switch (alt33) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:338:4: b= bitrange
					{
					pushFollow(FOLLOW_bitrange_in_lvalue2097);
					b=bitrange();
					state._fsp--;

					 value = b; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:339:4: ^( OP_DECLARATIVE_SIZE v= variable c= constant )
					{
					match(input,OP_DECLARATIVE_SIZE,FOLLOW_OP_DECLARATIVE_SIZE_in_lvalue2105); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_variable_in_lvalue2109);
					v=variable();
					state._fsp--;

					pushFollow(FOLLOW_constant_in_lvalue2113);
					c=constant();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = v + ":" + c; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:340:4: v= variable
					{
					pushFollow(FOLLOW_variable_in_lvalue2123);
					v=variable();
					state._fsp--;

					 value = v; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighEcho.g:341:4: s= sizedstar
					{
					pushFollow(FOLLOW_sizedstar_in_lvalue2132);
					s=sizedstar();
					state._fsp--;

					 value = s; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "lvalue"



	// $ANTLR start "bitrange"
	// ghidra/sleigh/grammar/SleighEcho.g:344:1: bitrange returns [String value] : ^( OP_BITRANGE v= variable a= constant b= constant ) ;
	public final String bitrange() throws RecognitionException {
		String value = null;


		String v =null;
		String a =null;
		String b =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:345:2: ( ^( OP_BITRANGE v= variable a= constant b= constant ) )
			// ghidra/sleigh/grammar/SleighEcho.g:345:4: ^( OP_BITRANGE v= variable a= constant b= constant )
			{
			match(input,OP_BITRANGE,FOLLOW_OP_BITRANGE_in_bitrange2150); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_variable_in_bitrange2154);
			v=variable();
			state._fsp--;

			pushFollow(FOLLOW_constant_in_bitrange2158);
			a=constant();
			state._fsp--;

			pushFollow(FOLLOW_constant_in_bitrange2162);
			b=constant();
			state._fsp--;

			match(input, Token.UP, null); 

			 value = v + "[" + a + "," + b + "]"; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "bitrange"



	// $ANTLR start "sizedstar"
	// ghidra/sleigh/grammar/SleighEcho.g:348:1: sizedstar returns [String value] : ( ^( OP_DEREFERENCE v= variable c= constant e= expr ) | ^( OP_DEREFERENCE v= variable e= expr ) | ^( OP_DEREFERENCE c= constant e= expr ) | ^( OP_DEREFERENCE e= expr ) );
	public final String sizedstar() throws RecognitionException {
		String value = null;


		String v =null;
		String c =null;
		String e =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:349:2: ( ^( OP_DEREFERENCE v= variable c= constant e= expr ) | ^( OP_DEREFERENCE v= variable e= expr ) | ^( OP_DEREFERENCE c= constant e= expr ) | ^( OP_DEREFERENCE e= expr ) )
			int alt34=4;
			alt34 = dfa34.predict(input);
			switch (alt34) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:349:4: ^( OP_DEREFERENCE v= variable c= constant e= expr )
					{
					match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstar2181); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_variable_in_sizedstar2185);
					v=variable();
					state._fsp--;

					pushFollow(FOLLOW_constant_in_sizedstar2189);
					c=constant();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_sizedstar2193);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "*[" + v + "]:" + c + " " + e; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:350:4: ^( OP_DEREFERENCE v= variable e= expr )
					{
					match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstar2202); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_variable_in_sizedstar2206);
					v=variable();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_sizedstar2210);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "*[" + v + "] " + e; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:351:4: ^( OP_DEREFERENCE c= constant e= expr )
					{
					match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstar2219); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_constant_in_sizedstar2223);
					c=constant();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_sizedstar2227);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "*:" + c + " " + e; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighEcho.g:352:4: ^( OP_DEREFERENCE e= expr )
					{
					match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstar2236); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_sizedstar2240);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "* " + e; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "sizedstar"



	// $ANTLR start "funcall"
	// ghidra/sleigh/grammar/SleighEcho.g:355:1: funcall : e= expr_apply ;
	public final void funcall() throws RecognitionException {
		String e =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:356:2: (e= expr_apply )
			// ghidra/sleigh/grammar/SleighEcho.g:356:4: e= expr_apply
			{
			pushFollow(FOLLOW_expr_apply_in_funcall2256);
			e=expr_apply();
			state._fsp--;

			 out(e + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "funcall"



	// $ANTLR start "build_stmt"
	// ghidra/sleigh/grammar/SleighEcho.g:359:1: build_stmt : ^( OP_BUILD v= variable ) ;
	public final void build_stmt() throws RecognitionException {
		String v =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:360:2: ( ^( OP_BUILD v= variable ) )
			// ghidra/sleigh/grammar/SleighEcho.g:360:4: ^( OP_BUILD v= variable )
			{
			match(input,OP_BUILD,FOLLOW_OP_BUILD_in_build_stmt2270); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_variable_in_build_stmt2274);
			v=variable();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("build " + v + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "build_stmt"



	// $ANTLR start "crossbuild_stmt"
	// ghidra/sleigh/grammar/SleighEcho.g:363:1: crossbuild_stmt : ^( OP_CROSSBUILD v= varnode n= variable ) ;
	public final void crossbuild_stmt() throws RecognitionException {
		String v =null;
		String n =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:364:2: ( ^( OP_CROSSBUILD v= varnode n= variable ) )
			// ghidra/sleigh/grammar/SleighEcho.g:364:4: ^( OP_CROSSBUILD v= varnode n= variable )
			{
			match(input,OP_CROSSBUILD,FOLLOW_OP_CROSSBUILD_in_crossbuild_stmt2289); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_varnode_in_crossbuild_stmt2293);
			v=varnode();
			state._fsp--;

			pushFollow(FOLLOW_variable_in_crossbuild_stmt2297);
			n=variable();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("crossbuild " + v + ", " + n + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "crossbuild_stmt"



	// $ANTLR start "goto_stmt"
	// ghidra/sleigh/grammar/SleighEcho.g:367:1: goto_stmt : ^( OP_GOTO j= jumpdest ) ;
	public final void goto_stmt() throws RecognitionException {
		String j =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:368:2: ( ^( OP_GOTO j= jumpdest ) )
			// ghidra/sleigh/grammar/SleighEcho.g:368:4: ^( OP_GOTO j= jumpdest )
			{
			match(input,OP_GOTO,FOLLOW_OP_GOTO_in_goto_stmt2312); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_jumpdest_in_goto_stmt2316);
			j=jumpdest();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("goto " + j + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "goto_stmt"



	// $ANTLR start "jumpdest"
	// ghidra/sleigh/grammar/SleighEcho.g:371:1: jumpdest returns [String value] : ( ^( OP_JUMPDEST_SYMBOL v= variable ) | ^( OP_JUMPDEST_DYNAMIC e= expr ) | ^( OP_JUMPDEST_ABSOLUTE i= integer ) | ^( OP_JUMPDEST_RELATIVE c= constant v= variable ) | ^( OP_JUMPDEST_LABEL l= label ) );
	public final String jumpdest() throws RecognitionException {
		String value = null;


		String v =null;
		String e =null;
		String i =null;
		String c =null;
		String l =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:372:2: ( ^( OP_JUMPDEST_SYMBOL v= variable ) | ^( OP_JUMPDEST_DYNAMIC e= expr ) | ^( OP_JUMPDEST_ABSOLUTE i= integer ) | ^( OP_JUMPDEST_RELATIVE c= constant v= variable ) | ^( OP_JUMPDEST_LABEL l= label ) )
			int alt35=5;
			switch ( input.LA(1) ) {
			case OP_JUMPDEST_SYMBOL:
				{
				alt35=1;
				}
				break;
			case OP_JUMPDEST_DYNAMIC:
				{
				alt35=2;
				}
				break;
			case OP_JUMPDEST_ABSOLUTE:
				{
				alt35=3;
				}
				break;
			case OP_JUMPDEST_RELATIVE:
				{
				alt35=4;
				}
				break;
			case OP_JUMPDEST_LABEL:
				{
				alt35=5;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 35, 0, input);
				throw nvae;
			}
			switch (alt35) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:372:4: ^( OP_JUMPDEST_SYMBOL v= variable )
					{
					match(input,OP_JUMPDEST_SYMBOL,FOLLOW_OP_JUMPDEST_SYMBOL_in_jumpdest2335); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_variable_in_jumpdest2339);
					v=variable();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = v; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:373:4: ^( OP_JUMPDEST_DYNAMIC e= expr )
					{
					match(input,OP_JUMPDEST_DYNAMIC,FOLLOW_OP_JUMPDEST_DYNAMIC_in_jumpdest2348); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_jumpdest2352);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "[" + e + "]"; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:374:4: ^( OP_JUMPDEST_ABSOLUTE i= integer )
					{
					match(input,OP_JUMPDEST_ABSOLUTE,FOLLOW_OP_JUMPDEST_ABSOLUTE_in_jumpdest2361); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_jumpdest2365);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = i; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighEcho.g:375:4: ^( OP_JUMPDEST_RELATIVE c= constant v= variable )
					{
					match(input,OP_JUMPDEST_RELATIVE,FOLLOW_OP_JUMPDEST_RELATIVE_in_jumpdest2374); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_constant_in_jumpdest2378);
					c=constant();
					state._fsp--;

					pushFollow(FOLLOW_variable_in_jumpdest2382);
					v=variable();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = c + "[" + v + "]"; 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighEcho.g:376:4: ^( OP_JUMPDEST_LABEL l= label )
					{
					match(input,OP_JUMPDEST_LABEL,FOLLOW_OP_JUMPDEST_LABEL_in_jumpdest2391); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_label_in_jumpdest2395);
					l=label();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "jumpdest"



	// $ANTLR start "cond_stmt"
	// ghidra/sleigh/grammar/SleighEcho.g:379:1: cond_stmt : ^( OP_IF e= expr goto_stmt ) ;
	public final void cond_stmt() throws RecognitionException {
		String e =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:380:2: ( ^( OP_IF e= expr goto_stmt ) )
			// ghidra/sleigh/grammar/SleighEcho.g:380:4: ^( OP_IF e= expr goto_stmt )
			{
			match(input,OP_IF,FOLLOW_OP_IF_in_cond_stmt2410); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_expr_in_cond_stmt2414);
			e=expr();
			state._fsp--;

			 ot("if (" + e + ") "); 
			pushFollow(FOLLOW_goto_stmt_in_cond_stmt2418);
			goto_stmt();
			state._fsp--;

			match(input, Token.UP, null); 

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "cond_stmt"



	// $ANTLR start "call_stmt"
	// ghidra/sleigh/grammar/SleighEcho.g:383:1: call_stmt : ^( OP_CALL j= jumpdest ) ;
	public final void call_stmt() throws RecognitionException {
		String j =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:384:2: ( ^( OP_CALL j= jumpdest ) )
			// ghidra/sleigh/grammar/SleighEcho.g:384:4: ^( OP_CALL j= jumpdest )
			{
			match(input,OP_CALL,FOLLOW_OP_CALL_in_call_stmt2431); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_jumpdest_in_call_stmt2435);
			j=jumpdest();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("call " + j + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "call_stmt"



	// $ANTLR start "return_stmt"
	// ghidra/sleigh/grammar/SleighEcho.g:387:1: return_stmt : ( ^( OP_RETURN e= expr ) | OP_RETURN );
	public final void return_stmt() throws RecognitionException {
		String e =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:388:2: ( ^( OP_RETURN e= expr ) | OP_RETURN )
			int alt36=2;
			int LA36_0 = input.LA(1);
			if ( (LA36_0==OP_RETURN) ) {
				int LA36_1 = input.LA(2);
				if ( (LA36_1==DOWN) ) {
					alt36=1;
				}
				else if ( (LA36_1==UP||LA36_1==OP_APPLY||LA36_1==OP_ASSIGN||(LA36_1 >= OP_BUILD && LA36_1 <= OP_CALL)||LA36_1==OP_CROSSBUILD||LA36_1==OP_EXPORT||LA36_1==OP_GOTO||LA36_1==OP_IF||LA36_1==OP_LABEL||LA36_1==OP_LOCAL||LA36_1==OP_RETURN||LA36_1==OP_SECTION_LABEL) ) {
					alt36=2;
				}

				else {
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

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 36, 0, input);
				throw nvae;
			}

			switch (alt36) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:388:4: ^( OP_RETURN e= expr )
					{
					match(input,OP_RETURN,FOLLOW_OP_RETURN_in_return_stmt2450); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_return_stmt2454);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 out("return [" + e + "];"); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:389:4: OP_RETURN
					{
					match(input,OP_RETURN,FOLLOW_OP_RETURN_in_return_stmt2462); 
					 out("return;"); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "return_stmt"



	// $ANTLR start "export"
	// ghidra/sleigh/grammar/SleighEcho.g:392:1: export : ^( OP_EXPORT e= expr ) ;
	public final void export() throws RecognitionException {
		String e =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:393:2: ( ^( OP_EXPORT e= expr ) )
			// ghidra/sleigh/grammar/SleighEcho.g:393:4: ^( OP_EXPORT e= expr )
			{
			match(input,OP_EXPORT,FOLLOW_OP_EXPORT_in_export2476); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_expr_in_export2480);
			e=expr();
			state._fsp--;

			match(input, Token.UP, null); 

			 out("export " + e + ";"); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "export"



	// $ANTLR start "expr"
	// ghidra/sleigh/grammar/SleighEcho.g:396:1: expr returns [String value] : ( ^( OP_BOOL_OR l= expr r= expr ) | ^( OP_BOOL_XOR l= expr r= expr ) | ^( OP_BOOL_AND l= expr r= expr ) | ^( OP_OR l= expr r= expr ) | ^( OP_XOR l= expr r= expr ) | ^( OP_AND l= expr r= expr ) | ^( OP_EQUAL l= expr r= expr ) | ^( OP_NOTEQUAL l= expr r= expr ) | ^( OP_FEQUAL l= expr r= expr ) | ^( OP_FNOTEQUAL l= expr r= expr ) | ^( OP_LESS l= expr r= expr ) | ^( OP_GREATEQUAL l= expr r= expr ) | ^( OP_LESSEQUAL l= expr r= expr ) | ^( OP_GREAT l= expr r= expr ) | ^( OP_SLESS l= expr r= expr ) | ^( OP_SGREATEQUAL l= expr r= expr ) | ^( OP_SLESSEQUAL l= expr r= expr ) | ^( OP_SGREAT l= expr r= expr ) | ^( OP_FLESS l= expr r= expr ) | ^( OP_FGREATEQUAL l= expr r= expr ) | ^( OP_FLESSEQUAL l= expr r= expr ) | ^( OP_FGREAT l= expr r= expr ) | ^( OP_LEFT l= expr r= expr ) | ^( OP_RIGHT l= expr r= expr ) | ^( OP_SRIGHT l= expr r= expr ) | ^( OP_ADD l= expr r= expr ) | ^( OP_SUB l= expr r= expr ) | ^( OP_FADD l= expr r= expr ) | ^( OP_FSUB l= expr r= expr ) | ^( OP_MULT l= expr r= expr ) | ^( OP_DIV l= expr r= expr ) | ^( OP_REM l= expr r= expr ) | ^( OP_SDIV l= expr r= expr ) | ^( OP_SREM l= expr r= expr ) | ^( OP_FMULT l= expr r= expr ) | ^( OP_FDIV l= expr r= expr ) | ^( OP_NOT l= expr ) | ^( OP_INVERT l= expr ) | ^( OP_NEGATE l= expr ) | ^( OP_FNEGATE l= expr ) |s= sizedstar |a= expr_apply |v= varnode |b= bitrange | ^( OP_PARENTHESIZED l= expr ) | ^( OP_BITRANGE2 n= identifier i= integer ) );
	public final String expr() throws RecognitionException {
		String value = null;


		String l =null;
		String r =null;
		String s =null;
		String a =null;
		String v =null;
		String b =null;
		String n =null;
		String i =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:397:2: ( ^( OP_BOOL_OR l= expr r= expr ) | ^( OP_BOOL_XOR l= expr r= expr ) | ^( OP_BOOL_AND l= expr r= expr ) | ^( OP_OR l= expr r= expr ) | ^( OP_XOR l= expr r= expr ) | ^( OP_AND l= expr r= expr ) | ^( OP_EQUAL l= expr r= expr ) | ^( OP_NOTEQUAL l= expr r= expr ) | ^( OP_FEQUAL l= expr r= expr ) | ^( OP_FNOTEQUAL l= expr r= expr ) | ^( OP_LESS l= expr r= expr ) | ^( OP_GREATEQUAL l= expr r= expr ) | ^( OP_LESSEQUAL l= expr r= expr ) | ^( OP_GREAT l= expr r= expr ) | ^( OP_SLESS l= expr r= expr ) | ^( OP_SGREATEQUAL l= expr r= expr ) | ^( OP_SLESSEQUAL l= expr r= expr ) | ^( OP_SGREAT l= expr r= expr ) | ^( OP_FLESS l= expr r= expr ) | ^( OP_FGREATEQUAL l= expr r= expr ) | ^( OP_FLESSEQUAL l= expr r= expr ) | ^( OP_FGREAT l= expr r= expr ) | ^( OP_LEFT l= expr r= expr ) | ^( OP_RIGHT l= expr r= expr ) | ^( OP_SRIGHT l= expr r= expr ) | ^( OP_ADD l= expr r= expr ) | ^( OP_SUB l= expr r= expr ) | ^( OP_FADD l= expr r= expr ) | ^( OP_FSUB l= expr r= expr ) | ^( OP_MULT l= expr r= expr ) | ^( OP_DIV l= expr r= expr ) | ^( OP_REM l= expr r= expr ) | ^( OP_SDIV l= expr r= expr ) | ^( OP_SREM l= expr r= expr ) | ^( OP_FMULT l= expr r= expr ) | ^( OP_FDIV l= expr r= expr ) | ^( OP_NOT l= expr ) | ^( OP_INVERT l= expr ) | ^( OP_NEGATE l= expr ) | ^( OP_FNEGATE l= expr ) |s= sizedstar |a= expr_apply |v= varnode |b= bitrange | ^( OP_PARENTHESIZED l= expr ) | ^( OP_BITRANGE2 n= identifier i= integer ) )
			int alt37=46;
			switch ( input.LA(1) ) {
			case OP_BOOL_OR:
				{
				alt37=1;
				}
				break;
			case OP_BOOL_XOR:
				{
				alt37=2;
				}
				break;
			case OP_BOOL_AND:
				{
				alt37=3;
				}
				break;
			case OP_OR:
				{
				alt37=4;
				}
				break;
			case OP_XOR:
				{
				alt37=5;
				}
				break;
			case OP_AND:
				{
				alt37=6;
				}
				break;
			case OP_EQUAL:
				{
				alt37=7;
				}
				break;
			case OP_NOTEQUAL:
				{
				alt37=8;
				}
				break;
			case OP_FEQUAL:
				{
				alt37=9;
				}
				break;
			case OP_FNOTEQUAL:
				{
				alt37=10;
				}
				break;
			case OP_LESS:
				{
				alt37=11;
				}
				break;
			case OP_GREATEQUAL:
				{
				alt37=12;
				}
				break;
			case OP_LESSEQUAL:
				{
				alt37=13;
				}
				break;
			case OP_GREAT:
				{
				alt37=14;
				}
				break;
			case OP_SLESS:
				{
				alt37=15;
				}
				break;
			case OP_SGREATEQUAL:
				{
				alt37=16;
				}
				break;
			case OP_SLESSEQUAL:
				{
				alt37=17;
				}
				break;
			case OP_SGREAT:
				{
				alt37=18;
				}
				break;
			case OP_FLESS:
				{
				alt37=19;
				}
				break;
			case OP_FGREATEQUAL:
				{
				alt37=20;
				}
				break;
			case OP_FLESSEQUAL:
				{
				alt37=21;
				}
				break;
			case OP_FGREAT:
				{
				alt37=22;
				}
				break;
			case OP_LEFT:
				{
				alt37=23;
				}
				break;
			case OP_RIGHT:
				{
				alt37=24;
				}
				break;
			case OP_SRIGHT:
				{
				alt37=25;
				}
				break;
			case OP_ADD:
				{
				alt37=26;
				}
				break;
			case OP_SUB:
				{
				alt37=27;
				}
				break;
			case OP_FADD:
				{
				alt37=28;
				}
				break;
			case OP_FSUB:
				{
				alt37=29;
				}
				break;
			case OP_MULT:
				{
				alt37=30;
				}
				break;
			case OP_DIV:
				{
				alt37=31;
				}
				break;
			case OP_REM:
				{
				alt37=32;
				}
				break;
			case OP_SDIV:
				{
				alt37=33;
				}
				break;
			case OP_SREM:
				{
				alt37=34;
				}
				break;
			case OP_FMULT:
				{
				alt37=35;
				}
				break;
			case OP_FDIV:
				{
				alt37=36;
				}
				break;
			case OP_NOT:
				{
				alt37=37;
				}
				break;
			case OP_INVERT:
				{
				alt37=38;
				}
				break;
			case OP_NEGATE:
				{
				alt37=39;
				}
				break;
			case OP_FNEGATE:
				{
				alt37=40;
				}
				break;
			case OP_DEREFERENCE:
				{
				alt37=41;
				}
				break;
			case OP_APPLY:
				{
				alt37=42;
				}
				break;
			case OP_ADDRESS_OF:
			case OP_BIN_CONSTANT:
			case OP_DEC_CONSTANT:
			case OP_HEX_CONSTANT:
			case OP_IDENTIFIER:
			case OP_TRUNCATION_SIZE:
			case OP_WILDCARD:
				{
				alt37=43;
				}
				break;
			case OP_BITRANGE:
				{
				alt37=44;
				}
				break;
			case OP_PARENTHESIZED:
				{
				alt37=45;
				}
				break;
			case OP_BITRANGE2:
				{
				alt37=46;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 37, 0, input);
				throw nvae;
			}
			switch (alt37) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:397:4: ^( OP_BOOL_OR l= expr r= expr )
					{
					match(input,OP_BOOL_OR,FOLLOW_OP_BOOL_OR_in_expr2499); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2503);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2507);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " || " + r; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:398:4: ^( OP_BOOL_XOR l= expr r= expr )
					{
					match(input,OP_BOOL_XOR,FOLLOW_OP_BOOL_XOR_in_expr2516); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2520);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2524);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " ^^ " + r; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:399:4: ^( OP_BOOL_AND l= expr r= expr )
					{
					match(input,OP_BOOL_AND,FOLLOW_OP_BOOL_AND_in_expr2533); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2537);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2541);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " && " + r; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighEcho.g:401:4: ^( OP_OR l= expr r= expr )
					{
					match(input,OP_OR,FOLLOW_OP_OR_in_expr2551); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2555);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2559);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " | " + r; 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighEcho.g:402:4: ^( OP_XOR l= expr r= expr )
					{
					match(input,OP_XOR,FOLLOW_OP_XOR_in_expr2568); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2572);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2576);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " ^ " + r; 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighEcho.g:403:4: ^( OP_AND l= expr r= expr )
					{
					match(input,OP_AND,FOLLOW_OP_AND_in_expr2585); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2589);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2593);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " & " + r; 
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighEcho.g:405:4: ^( OP_EQUAL l= expr r= expr )
					{
					match(input,OP_EQUAL,FOLLOW_OP_EQUAL_in_expr2603); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2607);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2611);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " == " + r; 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighEcho.g:406:4: ^( OP_NOTEQUAL l= expr r= expr )
					{
					match(input,OP_NOTEQUAL,FOLLOW_OP_NOTEQUAL_in_expr2620); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2624);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2628);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " != " + r; 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighEcho.g:407:4: ^( OP_FEQUAL l= expr r= expr )
					{
					match(input,OP_FEQUAL,FOLLOW_OP_FEQUAL_in_expr2637); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2641);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2645);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " f== " + r; 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighEcho.g:408:4: ^( OP_FNOTEQUAL l= expr r= expr )
					{
					match(input,OP_FNOTEQUAL,FOLLOW_OP_FNOTEQUAL_in_expr2654); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2658);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2662);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " f!= " + r; 
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighEcho.g:410:4: ^( OP_LESS l= expr r= expr )
					{
					match(input,OP_LESS,FOLLOW_OP_LESS_in_expr2672); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2676);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2680);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " < " + r; 
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighEcho.g:411:4: ^( OP_GREATEQUAL l= expr r= expr )
					{
					match(input,OP_GREATEQUAL,FOLLOW_OP_GREATEQUAL_in_expr2689); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2693);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2697);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " >= " + r; 
					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighEcho.g:412:4: ^( OP_LESSEQUAL l= expr r= expr )
					{
					match(input,OP_LESSEQUAL,FOLLOW_OP_LESSEQUAL_in_expr2706); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2710);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2714);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " <= " + r; 
					}
					break;
				case 14 :
					// ghidra/sleigh/grammar/SleighEcho.g:413:4: ^( OP_GREAT l= expr r= expr )
					{
					match(input,OP_GREAT,FOLLOW_OP_GREAT_in_expr2723); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2727);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2731);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " > " + r; 
					}
					break;
				case 15 :
					// ghidra/sleigh/grammar/SleighEcho.g:414:4: ^( OP_SLESS l= expr r= expr )
					{
					match(input,OP_SLESS,FOLLOW_OP_SLESS_in_expr2740); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2744);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2748);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " s< " + r; 
					}
					break;
				case 16 :
					// ghidra/sleigh/grammar/SleighEcho.g:415:4: ^( OP_SGREATEQUAL l= expr r= expr )
					{
					match(input,OP_SGREATEQUAL,FOLLOW_OP_SGREATEQUAL_in_expr2757); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2761);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2765);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " s>= " + r; 
					}
					break;
				case 17 :
					// ghidra/sleigh/grammar/SleighEcho.g:416:4: ^( OP_SLESSEQUAL l= expr r= expr )
					{
					match(input,OP_SLESSEQUAL,FOLLOW_OP_SLESSEQUAL_in_expr2774); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2778);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2782);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " s<= " + r; 
					}
					break;
				case 18 :
					// ghidra/sleigh/grammar/SleighEcho.g:417:4: ^( OP_SGREAT l= expr r= expr )
					{
					match(input,OP_SGREAT,FOLLOW_OP_SGREAT_in_expr2791); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2795);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2799);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " s> " + r; 
					}
					break;
				case 19 :
					// ghidra/sleigh/grammar/SleighEcho.g:418:4: ^( OP_FLESS l= expr r= expr )
					{
					match(input,OP_FLESS,FOLLOW_OP_FLESS_in_expr2808); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2812);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2816);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " f< " + r; 
					}
					break;
				case 20 :
					// ghidra/sleigh/grammar/SleighEcho.g:419:4: ^( OP_FGREATEQUAL l= expr r= expr )
					{
					match(input,OP_FGREATEQUAL,FOLLOW_OP_FGREATEQUAL_in_expr2825); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2829);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2833);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " f>= " + r; 
					}
					break;
				case 21 :
					// ghidra/sleigh/grammar/SleighEcho.g:420:4: ^( OP_FLESSEQUAL l= expr r= expr )
					{
					match(input,OP_FLESSEQUAL,FOLLOW_OP_FLESSEQUAL_in_expr2842); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2846);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2850);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " f<= " + r; 
					}
					break;
				case 22 :
					// ghidra/sleigh/grammar/SleighEcho.g:421:4: ^( OP_FGREAT l= expr r= expr )
					{
					match(input,OP_FGREAT,FOLLOW_OP_FGREAT_in_expr2859); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2863);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2867);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " f> " + r; 
					}
					break;
				case 23 :
					// ghidra/sleigh/grammar/SleighEcho.g:423:4: ^( OP_LEFT l= expr r= expr )
					{
					match(input,OP_LEFT,FOLLOW_OP_LEFT_in_expr2877); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2881);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2885);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " << " + r; 
					}
					break;
				case 24 :
					// ghidra/sleigh/grammar/SleighEcho.g:424:4: ^( OP_RIGHT l= expr r= expr )
					{
					match(input,OP_RIGHT,FOLLOW_OP_RIGHT_in_expr2894); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2898);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2902);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " >> " + r; 
					}
					break;
				case 25 :
					// ghidra/sleigh/grammar/SleighEcho.g:425:4: ^( OP_SRIGHT l= expr r= expr )
					{
					match(input,OP_SRIGHT,FOLLOW_OP_SRIGHT_in_expr2911); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2915);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2919);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " s>> " + r; 
					}
					break;
				case 26 :
					// ghidra/sleigh/grammar/SleighEcho.g:427:4: ^( OP_ADD l= expr r= expr )
					{
					match(input,OP_ADD,FOLLOW_OP_ADD_in_expr2929); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2933);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2937);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " + " + r; 
					}
					break;
				case 27 :
					// ghidra/sleigh/grammar/SleighEcho.g:428:4: ^( OP_SUB l= expr r= expr )
					{
					match(input,OP_SUB,FOLLOW_OP_SUB_in_expr2946); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2950);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2954);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " - " + r; 
					}
					break;
				case 28 :
					// ghidra/sleigh/grammar/SleighEcho.g:429:4: ^( OP_FADD l= expr r= expr )
					{
					match(input,OP_FADD,FOLLOW_OP_FADD_in_expr2963); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2967);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2971);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " f+ " + r; 
					}
					break;
				case 29 :
					// ghidra/sleigh/grammar/SleighEcho.g:430:4: ^( OP_FSUB l= expr r= expr )
					{
					match(input,OP_FSUB,FOLLOW_OP_FSUB_in_expr2980); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr2984);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr2988);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " f- " + r; 
					}
					break;
				case 30 :
					// ghidra/sleigh/grammar/SleighEcho.g:432:4: ^( OP_MULT l= expr r= expr )
					{
					match(input,OP_MULT,FOLLOW_OP_MULT_in_expr2998); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr3002);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr3006);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " * " + r; 
					}
					break;
				case 31 :
					// ghidra/sleigh/grammar/SleighEcho.g:433:5: ^( OP_DIV l= expr r= expr )
					{
					match(input,OP_DIV,FOLLOW_OP_DIV_in_expr3016); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr3020);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr3024);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " / " + r; 
					}
					break;
				case 32 :
					// ghidra/sleigh/grammar/SleighEcho.g:434:4: ^( OP_REM l= expr r= expr )
					{
					match(input,OP_REM,FOLLOW_OP_REM_in_expr3033); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr3037);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr3041);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " % " + r; 
					}
					break;
				case 33 :
					// ghidra/sleigh/grammar/SleighEcho.g:435:4: ^( OP_SDIV l= expr r= expr )
					{
					match(input,OP_SDIV,FOLLOW_OP_SDIV_in_expr3050); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr3054);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr3058);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " s/ " + r; 
					}
					break;
				case 34 :
					// ghidra/sleigh/grammar/SleighEcho.g:436:4: ^( OP_SREM l= expr r= expr )
					{
					match(input,OP_SREM,FOLLOW_OP_SREM_in_expr3067); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr3071);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr3075);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " s% " + r; 
					}
					break;
				case 35 :
					// ghidra/sleigh/grammar/SleighEcho.g:437:4: ^( OP_FMULT l= expr r= expr )
					{
					match(input,OP_FMULT,FOLLOW_OP_FMULT_in_expr3084); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr3088);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr3092);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " f* " + r; 
					}
					break;
				case 36 :
					// ghidra/sleigh/grammar/SleighEcho.g:438:4: ^( OP_FDIV l= expr r= expr )
					{
					match(input,OP_FDIV,FOLLOW_OP_FDIV_in_expr3101); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr3105);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr3109);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l + " f/ " + r; 
					}
					break;
				case 37 :
					// ghidra/sleigh/grammar/SleighEcho.g:440:4: ^( OP_NOT l= expr )
					{
					match(input,OP_NOT,FOLLOW_OP_NOT_in_expr3119); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr3123);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "!" + l; 
					}
					break;
				case 38 :
					// ghidra/sleigh/grammar/SleighEcho.g:441:4: ^( OP_INVERT l= expr )
					{
					match(input,OP_INVERT,FOLLOW_OP_INVERT_in_expr3132); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr3136);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "~" + l; 
					}
					break;
				case 39 :
					// ghidra/sleigh/grammar/SleighEcho.g:442:4: ^( OP_NEGATE l= expr )
					{
					match(input,OP_NEGATE,FOLLOW_OP_NEGATE_in_expr3145); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr3149);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "-" + l; 
					}
					break;
				case 40 :
					// ghidra/sleigh/grammar/SleighEcho.g:443:4: ^( OP_FNEGATE l= expr )
					{
					match(input,OP_FNEGATE,FOLLOW_OP_FNEGATE_in_expr3158); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr3162);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "f- " + l; 
					}
					break;
				case 41 :
					// ghidra/sleigh/grammar/SleighEcho.g:444:4: s= sizedstar
					{
					pushFollow(FOLLOW_sizedstar_in_expr3172);
					s=sizedstar();
					state._fsp--;

					 value = s; 
					}
					break;
				case 42 :
					// ghidra/sleigh/grammar/SleighEcho.g:446:4: a= expr_apply
					{
					pushFollow(FOLLOW_expr_apply_in_expr3182);
					a=expr_apply();
					state._fsp--;

					 value = a; 
					}
					break;
				case 43 :
					// ghidra/sleigh/grammar/SleighEcho.g:447:4: v= varnode
					{
					pushFollow(FOLLOW_varnode_in_expr3191);
					v=varnode();
					state._fsp--;

					 value = v; 
					}
					break;
				case 44 :
					// ghidra/sleigh/grammar/SleighEcho.g:448:4: b= bitrange
					{
					pushFollow(FOLLOW_bitrange_in_expr3200);
					b=bitrange();
					state._fsp--;

					 value = b; 
					}
					break;
				case 45 :
					// ghidra/sleigh/grammar/SleighEcho.g:449:4: ^( OP_PARENTHESIZED l= expr )
					{
					match(input,OP_PARENTHESIZED,FOLLOW_OP_PARENTHESIZED_in_expr3208); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr3212);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "(" + l + ")"; 
					}
					break;
				case 46 :
					// ghidra/sleigh/grammar/SleighEcho.g:450:4: ^( OP_BITRANGE2 n= identifier i= integer )
					{
					match(input,OP_BITRANGE2,FOLLOW_OP_BITRANGE2_in_expr3221); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_identifier_in_expr3225);
					n=identifier();
					state._fsp--;

					pushFollow(FOLLOW_integer_in_expr3229);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = n + ":" + i; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "expr"



	// $ANTLR start "expr_apply"
	// ghidra/sleigh/grammar/SleighEcho.g:453:1: expr_apply returns [String value] : ^( OP_APPLY n= identifier o= expr_operands ) ;
	public final String expr_apply() throws RecognitionException {
		String value = null;


		String n =null;
		String o =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:454:2: ( ^( OP_APPLY n= identifier o= expr_operands ) )
			// ghidra/sleigh/grammar/SleighEcho.g:454:4: ^( OP_APPLY n= identifier o= expr_operands )
			{
			match(input,OP_APPLY,FOLLOW_OP_APPLY_in_expr_apply3248); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifier_in_expr_apply3252);
			n=identifier();
			state._fsp--;

			pushFollow(FOLLOW_expr_operands_in_expr_apply3256);
			o=expr_operands();
			state._fsp--;

			match(input, Token.UP, null); 

			 value = n + "(" + o + ")"; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "expr_apply"



	// $ANTLR start "expr_operands"
	// ghidra/sleigh/grammar/SleighEcho.g:457:1: expr_operands returns [String value] : (e= expr )* ;
	public final String expr_operands() throws RecognitionException {
		String value = null;


		String e =null;


				String comma = "";
				value = "";
			
		try {
			// ghidra/sleigh/grammar/SleighEcho.g:462:2: ( (e= expr )* )
			// ghidra/sleigh/grammar/SleighEcho.g:462:4: (e= expr )*
			{
			// ghidra/sleigh/grammar/SleighEcho.g:462:4: (e= expr )*
			loop38:
			while (true) {
				int alt38=2;
				int LA38_0 = input.LA(1);
				if ( ((LA38_0 >= OP_ADD && LA38_0 <= OP_ADDRESS_OF)||(LA38_0 >= OP_AND && LA38_0 <= OP_APPLY)||(LA38_0 >= OP_BIN_CONSTANT && LA38_0 <= OP_BITRANGE2)||(LA38_0 >= OP_BOOL_AND && LA38_0 <= OP_BOOL_XOR)||LA38_0==OP_DEC_CONSTANT||LA38_0==OP_DEREFERENCE||LA38_0==OP_DIV||LA38_0==OP_EQUAL||(LA38_0 >= OP_FADD && LA38_0 <= OP_FGREATEQUAL)||(LA38_0 >= OP_FLESS && LA38_0 <= OP_FSUB)||(LA38_0 >= OP_GREAT && LA38_0 <= OP_GREATEQUAL)||(LA38_0 >= OP_HEX_CONSTANT && LA38_0 <= OP_IDENTIFIER)||LA38_0==OP_INVERT||(LA38_0 >= OP_LEFT && LA38_0 <= OP_LESSEQUAL)||LA38_0==OP_MULT||LA38_0==OP_NEGATE||(LA38_0 >= OP_NOT && LA38_0 <= OP_NOTEQUAL)||(LA38_0 >= OP_OR && LA38_0 <= OP_PARENTHESIZED)||LA38_0==OP_REM||(LA38_0 >= OP_RIGHT && LA38_0 <= OP_SDIV)||(LA38_0 >= OP_SGREAT && LA38_0 <= OP_SGREATEQUAL)||(LA38_0 >= OP_SLESS && LA38_0 <= OP_SLESSEQUAL)||(LA38_0 >= OP_SREM && LA38_0 <= OP_SRIGHT)||LA38_0==OP_SUB||LA38_0==OP_TRUNCATION_SIZE||LA38_0==OP_WILDCARD||LA38_0==OP_XOR) ) {
					alt38=1;
				}

				switch (alt38) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:462:5: e= expr
					{
					pushFollow(FOLLOW_expr_in_expr_operands3283);
					e=expr();
					state._fsp--;

					 value += comma + e; comma = ","; 
					}
					break;

				default :
					break loop38;
				}
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "expr_operands"



	// $ANTLR start "varnode"
	// ghidra/sleigh/grammar/SleighEcho.g:465:1: varnode returns [String value] : (s= symbol | ^( OP_TRUNCATION_SIZE s= symbol c= constant ) | ^( OP_ADDRESS_OF ^( OP_SIZING_SIZE c= constant ) v= varnode ) | ^( OP_ADDRESS_OF v= varnode ) );
	public final String varnode() throws RecognitionException {
		String value = null;


		String s =null;
		String c =null;
		String v =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:466:2: (s= symbol | ^( OP_TRUNCATION_SIZE s= symbol c= constant ) | ^( OP_ADDRESS_OF ^( OP_SIZING_SIZE c= constant ) v= varnode ) | ^( OP_ADDRESS_OF v= varnode ) )
			int alt39=4;
			switch ( input.LA(1) ) {
			case OP_BIN_CONSTANT:
			case OP_DEC_CONSTANT:
			case OP_HEX_CONSTANT:
			case OP_IDENTIFIER:
			case OP_WILDCARD:
				{
				alt39=1;
				}
				break;
			case OP_TRUNCATION_SIZE:
				{
				alt39=2;
				}
				break;
			case OP_ADDRESS_OF:
				{
				int LA39_3 = input.LA(2);
				if ( (LA39_3==DOWN) ) {
					int LA39_4 = input.LA(3);
					if ( (LA39_4==OP_SIZING_SIZE) ) {
						alt39=3;
					}
					else if ( (LA39_4==OP_ADDRESS_OF||LA39_4==OP_BIN_CONSTANT||LA39_4==OP_DEC_CONSTANT||(LA39_4 >= OP_HEX_CONSTANT && LA39_4 <= OP_IDENTIFIER)||LA39_4==OP_TRUNCATION_SIZE||LA39_4==OP_WILDCARD) ) {
						alt39=4;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 39, 4, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 39, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 39, 0, input);
				throw nvae;
			}
			switch (alt39) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:466:4: s= symbol
					{
					pushFollow(FOLLOW_symbol_in_varnode3304);
					s=symbol();
					state._fsp--;

					 value = s; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:467:4: ^( OP_TRUNCATION_SIZE s= symbol c= constant )
					{
					match(input,OP_TRUNCATION_SIZE,FOLLOW_OP_TRUNCATION_SIZE_in_varnode3312); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_symbol_in_varnode3316);
					s=symbol();
					state._fsp--;

					pushFollow(FOLLOW_constant_in_varnode3320);
					c=constant();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = s + ":" + c; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:468:4: ^( OP_ADDRESS_OF ^( OP_SIZING_SIZE c= constant ) v= varnode )
					{
					match(input,OP_ADDRESS_OF,FOLLOW_OP_ADDRESS_OF_in_varnode3329); 
					match(input, Token.DOWN, null); 
					match(input,OP_SIZING_SIZE,FOLLOW_OP_SIZING_SIZE_in_varnode3332); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_constant_in_varnode3336);
					c=constant();
					state._fsp--;

					match(input, Token.UP, null); 

					pushFollow(FOLLOW_varnode_in_varnode3341);
					v=varnode();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "&:" + c + " " + v; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighEcho.g:469:4: ^( OP_ADDRESS_OF v= varnode )
					{
					match(input,OP_ADDRESS_OF,FOLLOW_OP_ADDRESS_OF_in_varnode3350); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_varnode_in_varnode3354);
					v=varnode();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = "&" + " " + v; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "varnode"



	// $ANTLR start "symbol"
	// ghidra/sleigh/grammar/SleighEcho.g:472:1: symbol returns [String value] : (n= identifier |i= integer );
	public final String symbol() throws RecognitionException {
		String value = null;


		String n =null;
		String i =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:473:2: (n= identifier |i= integer )
			int alt40=2;
			int LA40_0 = input.LA(1);
			if ( (LA40_0==OP_IDENTIFIER||LA40_0==OP_WILDCARD) ) {
				alt40=1;
			}
			else if ( (LA40_0==OP_BIN_CONSTANT||LA40_0==OP_DEC_CONSTANT||LA40_0==OP_HEX_CONSTANT) ) {
				alt40=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 40, 0, input);
				throw nvae;
			}

			switch (alt40) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:473:4: n= identifier
					{
					pushFollow(FOLLOW_identifier_in_symbol3374);
					n=identifier();
					state._fsp--;

					value = n; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:474:4: i= integer
					{
					pushFollow(FOLLOW_integer_in_symbol3383);
					i=integer();
					state._fsp--;

					 value = i; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "symbol"



	// $ANTLR start "variable"
	// ghidra/sleigh/grammar/SleighEcho.g:477:1: variable returns [String value] : n= identifier ;
	public final String variable() throws RecognitionException {
		String value = null;


		String n =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:478:2: (n= identifier )
			// ghidra/sleigh/grammar/SleighEcho.g:478:4: n= identifier
			{
			pushFollow(FOLLOW_identifier_in_variable3402);
			n=identifier();
			state._fsp--;

			 value = n; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "variable"



	// $ANTLR start "constant"
	// ghidra/sleigh/grammar/SleighEcho.g:481:1: constant returns [String value] : i= integer ;
	public final String constant() throws RecognitionException {
		String value = null;


		String i =null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:482:2: (i= integer )
			// ghidra/sleigh/grammar/SleighEcho.g:482:4: i= integer
			{
			pushFollow(FOLLOW_integer_in_constant3421);
			i=integer();
			state._fsp--;

			 value = i; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "constant"



	// $ANTLR start "qstring"
	// ghidra/sleigh/grammar/SleighEcho.g:485:1: qstring returns [String value] : ^( OP_QSTRING s= . ) ;
	public final String qstring() throws RecognitionException {
		String value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:486:2: ( ^( OP_QSTRING s= . ) )
			// ghidra/sleigh/grammar/SleighEcho.g:486:4: ^( OP_QSTRING s= . )
			{
			match(input,OP_QSTRING,FOLLOW_OP_QSTRING_in_qstring3439); 
			match(input, Token.DOWN, null); 
			s=(CommonTree)input.LT(1);
			matchAny(input); 
			match(input, Token.UP, null); 

			 value = "\"" + s.getText() + "\""; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "qstring"



	// $ANTLR start "identifier"
	// ghidra/sleigh/grammar/SleighEcho.g:489:1: identifier returns [String value] : ( ^( OP_IDENTIFIER s= . ) | OP_WILDCARD );
	public final String identifier() throws RecognitionException {
		String value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:490:2: ( ^( OP_IDENTIFIER s= . ) | OP_WILDCARD )
			int alt41=2;
			int LA41_0 = input.LA(1);
			if ( (LA41_0==OP_IDENTIFIER) ) {
				alt41=1;
			}
			else if ( (LA41_0==OP_WILDCARD) ) {
				alt41=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 41, 0, input);
				throw nvae;
			}

			switch (alt41) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:490:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_identifier3462); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = s.getText(); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:491:4: OP_WILDCARD
					{
					match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_identifier3474); 
					 value = "_"; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "identifier"



	// $ANTLR start "integer"
	// ghidra/sleigh/grammar/SleighEcho.g:494:1: integer returns [String value] : ( ^( OP_HEX_CONSTANT s= . ) | ^( OP_DEC_CONSTANT s= . ) | ^( OP_BIN_CONSTANT s= . ) );
	public final String integer() throws RecognitionException {
		String value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighEcho.g:495:2: ( ^( OP_HEX_CONSTANT s= . ) | ^( OP_DEC_CONSTANT s= . ) | ^( OP_BIN_CONSTANT s= . ) )
			int alt42=3;
			switch ( input.LA(1) ) {
			case OP_HEX_CONSTANT:
				{
				alt42=1;
				}
				break;
			case OP_DEC_CONSTANT:
				{
				alt42=2;
				}
				break;
			case OP_BIN_CONSTANT:
				{
				alt42=3;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 42, 0, input);
				throw nvae;
			}
			switch (alt42) {
				case 1 :
					// ghidra/sleigh/grammar/SleighEcho.g:495:4: ^( OP_HEX_CONSTANT s= . )
					{
					match(input,OP_HEX_CONSTANT,FOLLOW_OP_HEX_CONSTANT_in_integer3492); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = s.getText(); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighEcho.g:496:4: ^( OP_DEC_CONSTANT s= . )
					{
					match(input,OP_DEC_CONSTANT,FOLLOW_OP_DEC_CONSTANT_in_integer3505); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = s.getText(); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighEcho.g:497:4: ^( OP_BIN_CONSTANT s= . )
					{
					match(input,OP_BIN_CONSTANT,FOLLOW_OP_BIN_CONSTANT_in_integer3518); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = s.getText(); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "integer"

	// Delegated rules


	protected DFA32 dfa32 = new DFA32(this);
	protected DFA34 dfa34 = new DFA34(this);
	static final String DFA32_eotS =
		"\15\uffff";
	static final String DFA32_eofS =
		"\15\uffff";
	static final String DFA32_minS =
		"\1\u009a\1\2\1\u008b\1\2\1\3\1\4\2\uffff\1\2\1\4\3\3";
	static final String DFA32_maxS =
		"\1\u009a\1\2\1\u00cc\1\2\1\u008a\1\u00ee\2\uffff\1\3\1\u00ee\1\u008a\1"+
		"\u00ee\1\3";
	static final String DFA32_acceptS =
		"\6\uffff\1\1\1\2\5\uffff";
	static final String DFA32_specialS =
		"\15\uffff}>";
	static final String[] DFA32_transitionS = {
			"\1\1",
			"\1\2",
			"\1\3\100\uffff\1\4",
			"\1\5",
			"\1\7\127\uffff\1\6\21\uffff\1\6\34\uffff\1\6",
			"\u00eb\10",
			"",
			"",
			"\1\11\1\12",
			"\u00eb\13",
			"\1\7\127\uffff\1\6\21\uffff\1\6\34\uffff\1\6",
			"\1\14\u00eb\13",
			"\1\12"
	};

	static final short[] DFA32_eot = DFA.unpackEncodedString(DFA32_eotS);
	static final short[] DFA32_eof = DFA.unpackEncodedString(DFA32_eofS);
	static final char[] DFA32_min = DFA.unpackEncodedStringToUnsignedChars(DFA32_minS);
	static final char[] DFA32_max = DFA.unpackEncodedStringToUnsignedChars(DFA32_maxS);
	static final short[] DFA32_accept = DFA.unpackEncodedString(DFA32_acceptS);
	static final short[] DFA32_special = DFA.unpackEncodedString(DFA32_specialS);
	static final short[][] DFA32_transition;

	static {
		int numStates = DFA32_transitionS.length;
		DFA32_transition = new short[numStates][];
		for (int i=0; i<numStates; i++) {
			DFA32_transition[i] = DFA.unpackEncodedString(DFA32_transitionS[i]);
		}
	}

	protected class DFA32 extends DFA {

		public DFA32(BaseRecognizer recognizer) {
			this.recognizer = recognizer;
			this.decisionNumber = 32;
			this.eot = DFA32_eot;
			this.eof = DFA32_eof;
			this.min = DFA32_min;
			this.max = DFA32_max;
			this.accept = DFA32_accept;
			this.special = DFA32_special;
			this.transition = DFA32_transition;
		}
		@Override
		public String getDescription() {
			return "332:1: declaration : ( ^( OP_LOCAL v= variable a= constant ) | ^( OP_LOCAL v= variable ) );";
		}
	}

	static final String DFA34_eotS =
		"\71\uffff";
	static final String DFA34_eofS =
		"\71\uffff";
	static final String DFA34_minS =
		"\1\157\1\2\1\123\1\2\1\3\3\2\1\uffff\1\4\3\2\1\uffff\3\4\1\2\3\4\3\2\1"+
		"\4\1\3\3\2\1\4\1\3\1\4\1\3\1\4\2\3\1\4\1\3\1\4\1\3\1\4\2\3\1\uffff\4\3"+
		"\1\uffff\10\3";
	static final String DFA34_maxS =
		"\1\157\1\2\1\u00cf\1\2\1\u00cf\3\2\1\uffff\1\u00ee\3\2\1\uffff\3\u00ee"+
		"\1\3\3\u00ee\3\3\1\u00ee\1\u00cf\3\3\1\u00ee\1\u00cf\1\u00ee\1\u00cf\1"+
		"\u00ee\1\u00cf\2\u00ee\1\u00cf\1\u00ee\1\u00cf\1\u00ee\1\u00cf\1\u00ee"+
		"\1\uffff\2\u00ee\1\3\1\u00ee\1\uffff\2\u00ee\6\3";
	static final String DFA34_acceptS =
		"\10\uffff\1\4\4\uffff\1\2\35\uffff\1\3\4\uffff\1\1\10\uffff";
	static final String DFA34_specialS =
		"\71\uffff}>";
	static final String[] DFA34_transitionS = {
			"\1\1",
			"\1\2",
			"\2\10\1\uffff\2\10\3\uffff\1\7\2\10\2\uffff\3\10\12\uffff\1\6\1\uffff"+
			"\1\10\1\uffff\1\10\4\uffff\1\10\1\uffff\5\10\3\uffff\6\10\1\uffff\2\10"+
			"\1\uffff\1\5\1\3\3\uffff\1\10\6\uffff\3\10\3\uffff\1\10\1\uffff\1\10"+
			"\3\uffff\2\10\3\uffff\2\10\3\uffff\1\10\1\uffff\2\10\3\uffff\2\10\3\uffff"+
			"\2\10\2\uffff\2\10\2\uffff\1\10\4\uffff\1\10\6\uffff\1\4\2\uffff\1\10",
			"\1\11",
			"\1\10\117\uffff\2\15\1\uffff\2\15\3\uffff\1\14\2\15\2\uffff\3\15\12"+
			"\uffff\1\13\1\uffff\1\15\1\uffff\1\15\4\uffff\1\15\1\uffff\5\15\3\uffff"+
			"\6\15\1\uffff\2\15\1\uffff\1\12\1\15\3\uffff\1\15\6\uffff\3\15\3\uffff"+
			"\1\15\1\uffff\1\15\3\uffff\2\15\3\uffff\2\15\3\uffff\1\15\1\uffff\2\15"+
			"\3\uffff\2\15\3\uffff\2\15\2\uffff\2\15\2\uffff\1\15\4\uffff\1\15\6\uffff"+
			"\1\15\2\uffff\1\15",
			"\1\16",
			"\1\17",
			"\1\20",
			"",
			"\u00eb\21",
			"\1\22",
			"\1\23",
			"\1\24",
			"",
			"\u00eb\25",
			"\u00eb\26",
			"\u00eb\27",
			"\1\30\1\31",
			"\u00eb\32",
			"\u00eb\33",
			"\u00eb\34",
			"\1\35\1\36",
			"\1\37\1\40",
			"\1\41\1\42",
			"\u00eb\43",
			"\1\10\117\uffff\2\15\1\uffff\2\15\3\uffff\1\14\2\15\2\uffff\3\15\12"+
			"\uffff\1\13\1\uffff\1\15\1\uffff\1\15\4\uffff\1\15\1\uffff\5\15\3\uffff"+
			"\6\15\1\uffff\2\15\1\uffff\1\12\1\15\3\uffff\1\15\6\uffff\3\15\3\uffff"+
			"\1\15\1\uffff\1\15\3\uffff\2\15\3\uffff\2\15\3\uffff\1\15\1\uffff\2\15"+
			"\3\uffff\2\15\3\uffff\2\15\2\uffff\2\15\2\uffff\1\15\4\uffff\1\15\6\uffff"+
			"\1\15\2\uffff\1\15",
			"\1\44\1\45",
			"\1\46\1\47",
			"\1\50\1\51",
			"\u00eb\52",
			"\1\10\117\uffff\2\53\1\uffff\2\53\3\uffff\3\53\2\uffff\3\53\12\uffff"+
			"\1\53\1\uffff\1\53\1\uffff\1\53\4\uffff\1\53\1\uffff\5\53\3\uffff\6\53"+
			"\1\uffff\2\53\1\uffff\2\53\3\uffff\1\53\6\uffff\3\53\3\uffff\1\53\1\uffff"+
			"\1\53\3\uffff\2\53\3\uffff\2\53\3\uffff\1\53\1\uffff\2\53\3\uffff\2\53"+
			"\3\uffff\2\53\2\uffff\2\53\2\uffff\1\53\4\uffff\1\53\6\uffff\1\53\2\uffff"+
			"\1\53",
			"\u00eb\54",
			"\1\10\117\uffff\2\53\1\uffff\2\53\3\uffff\3\53\2\uffff\3\53\12\uffff"+
			"\1\53\1\uffff\1\53\1\uffff\1\53\4\uffff\1\53\1\uffff\5\53\3\uffff\6\53"+
			"\1\uffff\2\53\1\uffff\2\53\3\uffff\1\53\6\uffff\3\53\3\uffff\1\53\1\uffff"+
			"\1\53\3\uffff\2\53\3\uffff\2\53\3\uffff\1\53\1\uffff\2\53\3\uffff\2\53"+
			"\3\uffff\2\53\2\uffff\2\53\2\uffff\1\53\4\uffff\1\53\6\uffff\1\53\2\uffff"+
			"\1\53",
			"\u00eb\55",
			"\1\10\117\uffff\2\53\1\uffff\2\53\3\uffff\3\53\2\uffff\3\53\12\uffff"+
			"\1\53\1\uffff\1\53\1\uffff\1\53\4\uffff\1\53\1\uffff\5\53\3\uffff\6\53"+
			"\1\uffff\2\53\1\uffff\2\53\3\uffff\1\53\6\uffff\3\53\3\uffff\1\53\1\uffff"+
			"\1\53\3\uffff\2\53\3\uffff\2\53\3\uffff\1\53\1\uffff\2\53\3\uffff\2\53"+
			"\3\uffff\2\53\2\uffff\2\53\2\uffff\1\53\4\uffff\1\53\6\uffff\1\53\2\uffff"+
			"\1\53",
			"\1\56\u00eb\43",
			"\u00eb\57",
			"\1\15\117\uffff\2\60\1\uffff\2\60\3\uffff\3\60\2\uffff\3\60\12\uffff"+
			"\1\60\1\uffff\1\60\1\uffff\1\60\4\uffff\1\60\1\uffff\5\60\3\uffff\6\60"+
			"\1\uffff\2\60\1\uffff\2\60\3\uffff\1\60\6\uffff\3\60\3\uffff\1\60\1\uffff"+
			"\1\60\3\uffff\2\60\3\uffff\2\60\3\uffff\1\60\1\uffff\2\60\3\uffff\2\60"+
			"\3\uffff\2\60\2\uffff\2\60\2\uffff\1\60\4\uffff\1\60\6\uffff\1\60\2\uffff"+
			"\1\60",
			"\u00eb\61",
			"\1\15\117\uffff\2\60\1\uffff\2\60\3\uffff\3\60\2\uffff\3\60\12\uffff"+
			"\1\60\1\uffff\1\60\1\uffff\1\60\4\uffff\1\60\1\uffff\5\60\3\uffff\6\60"+
			"\1\uffff\2\60\1\uffff\2\60\3\uffff\1\60\6\uffff\3\60\3\uffff\1\60\1\uffff"+
			"\1\60\3\uffff\2\60\3\uffff\2\60\3\uffff\1\60\1\uffff\2\60\3\uffff\2\60"+
			"\3\uffff\2\60\2\uffff\2\60\2\uffff\1\60\4\uffff\1\60\6\uffff\1\60\2\uffff"+
			"\1\60",
			"\u00eb\62",
			"\1\15\117\uffff\2\60\1\uffff\2\60\3\uffff\3\60\2\uffff\3\60\12\uffff"+
			"\1\60\1\uffff\1\60\1\uffff\1\60\4\uffff\1\60\1\uffff\5\60\3\uffff\6\60"+
			"\1\uffff\2\60\1\uffff\2\60\3\uffff\1\60\6\uffff\3\60\3\uffff\1\60\1\uffff"+
			"\1\60\3\uffff\2\60\3\uffff\2\60\3\uffff\1\60\1\uffff\2\60\3\uffff\2\60"+
			"\3\uffff\2\60\2\uffff\2\60\2\uffff\1\60\4\uffff\1\60\6\uffff\1\60\2\uffff"+
			"\1\60",
			"\1\63\u00eb\52",
			"",
			"\1\64\u00eb\54",
			"\1\65\u00eb\55",
			"\1\31",
			"\1\66\u00eb\57",
			"",
			"\1\67\u00eb\61",
			"\1\70\u00eb\62",
			"\1\36",
			"\1\40",
			"\1\42",
			"\1\45",
			"\1\47",
			"\1\51"
	};

	static final short[] DFA34_eot = DFA.unpackEncodedString(DFA34_eotS);
	static final short[] DFA34_eof = DFA.unpackEncodedString(DFA34_eofS);
	static final char[] DFA34_min = DFA.unpackEncodedStringToUnsignedChars(DFA34_minS);
	static final char[] DFA34_max = DFA.unpackEncodedStringToUnsignedChars(DFA34_maxS);
	static final short[] DFA34_accept = DFA.unpackEncodedString(DFA34_acceptS);
	static final short[] DFA34_special = DFA.unpackEncodedString(DFA34_specialS);
	static final short[][] DFA34_transition;

	static {
		int numStates = DFA34_transitionS.length;
		DFA34_transition = new short[numStates][];
		for (int i=0; i<numStates; i++) {
			DFA34_transition[i] = DFA.unpackEncodedString(DFA34_transitionS[i]);
		}
	}

	protected class DFA34 extends DFA {

		public DFA34(BaseRecognizer recognizer) {
			this.recognizer = recognizer;
			this.decisionNumber = 34;
			this.eot = DFA34_eot;
			this.eof = DFA34_eof;
			this.min = DFA34_min;
			this.max = DFA34_max;
			this.accept = DFA34_accept;
			this.special = DFA34_special;
			this.transition = DFA34_transition;
		}
		@Override
		public String getDescription() {
			return "348:1: sizedstar returns [String value] : ( ^( OP_DEREFERENCE v= variable c= constant e= expr ) | ^( OP_DEREFERENCE v= variable e= expr ) | ^( OP_DEREFERENCE c= constant e= expr ) | ^( OP_DEREFERENCE e= expr ) );";
		}
	}

	public static final BitSet FOLLOW_endiandef_in_root42 = new BitSet(new long[]{0x0000000000000002L,0x000000C040200000L,0x0400040028000000L,0x0000000000000718L});
	public static final BitSet FOLLOW_definition_in_root48 = new BitSet(new long[]{0x0000000000000002L,0x000000C040200000L,0x0400040028000000L,0x0000000000000718L});
	public static final BitSet FOLLOW_constructorlike_in_root54 = new BitSet(new long[]{0x0000000000000002L,0x000000C040200000L,0x0400040028000000L,0x0000000000000718L});
	public static final BitSet FOLLOW_OP_ENDIAN_in_endiandef71 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_endian_in_endiandef75 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_aligndef_in_definition106 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_tokendef_in_definition111 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_contextdef_in_definition116 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_spacedef_in_definition121 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_varnodedef_in_definition126 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_bitrangedef_in_definition131 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pcodeopdef_in_definition136 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_valueattach_in_definition141 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_nameattach_in_definition146 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_varattach_in_definition151 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_ALIGNMENT_in_aligndef166 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_aligndef170 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_TOKEN_in_tokendef185 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_tokendef189 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_tokendef193 = new BitSet(new long[]{0x0000000000000000L,0x4000000000000000L});
	public static final BitSet FOLLOW_fielddefs_in_tokendef197 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_TOKEN_ENDIAN_in_tokendef206 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_tokendef210 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_tokendef214 = new BitSet(new long[]{0x0000000000000000L,0x0000000004000000L,0x0000000002000000L});
	public static final BitSet FOLLOW_endian_in_tokendef218 = new BitSet(new long[]{0x0000000000000000L,0x4000000000000000L});
	public static final BitSet FOLLOW_fielddefs_in_tokendef222 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FIELDDEFS_in_fielddefs235 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_fielddef_in_fielddefs237 = new BitSet(new long[]{0x0000000000000008L,0x2000000000000000L});
	public static final BitSet FOLLOW_OP_FIELDDEF_in_fielddef253 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_fielddef257 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_fielddef261 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_fielddef265 = new BitSet(new long[]{0x0000000000000000L,0x8000000000000000L,0x0000004000000000L});
	public static final BitSet FOLLOW_fieldmods_in_fielddef269 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FIELD_MODS_in_fieldmods294 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_fieldmod_in_fieldmods301 = new BitSet(new long[]{0x0000000000000008L,0x0000080000000000L,0x0020000100000200L});
	public static final BitSet FOLLOW_OP_NO_FIELD_MOD_in_fieldmods318 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_SIGNED_in_fieldmod343 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NOFLOW_in_fieldmod355 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_HEX_in_fieldmod367 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_DEC_in_fieldmod379 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_CONTEXT_in_contextdef396 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_contextdef400 = new BitSet(new long[]{0x0000000000000000L,0x4000000000000000L});
	public static final BitSet FOLLOW_fielddefs_in_contextdef404 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SPACE_in_spacedef417 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_spacedef421 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0800000000000000L});
	public static final BitSet FOLLOW_spacemods_in_spacedef425 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SPACEMODS_in_spacemods449 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_spacemod_in_spacemods454 = new BitSet(new long[]{0x0000000000000008L,0x0000400000000000L,0x0040000000000000L,0x0000000000004040L});
	public static final BitSet FOLLOW_typemod_in_spacemod476 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_sizemod_in_spacemod485 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_wordsizemod_in_spacemod494 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_DEFAULT_in_spacemod501 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_TYPE_in_typemod519 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_type_in_typemod523 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_identifier_in_type543 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_SIZE_in_sizemod561 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_sizemod565 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_WORDSIZE_in_wordsizemod584 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_wordsizemod588 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_VARNODE_in_varnodedef603 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_varnodedef607 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_varnodedef611 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_varnodedef615 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000001000L});
	public static final BitSet FOLLOW_identifierlist_in_varnodedef619 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_LIST_in_identifierlist638 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_identifierlist645 = new BitSet(new long[]{0x0000000000000008L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_OP_STRING_OR_IDENT_LIST_in_stringoridentlist669 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_stringorident_in_stringoridentlist676 = new BitSet(new long[]{0x0000000000000008L,0x0000000000000000L,0x0000080000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_identifier_in_stringorident701 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_qstring_in_stringorident710 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_BITRANGES_in_bitrangedef724 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_bitranges_in_bitrangedef728 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_sbitrange_in_bitranges748 = new BitSet(new long[]{0x0000000000000002L,0x0000000010000000L});
	public static final BitSet FOLLOW_OP_BITRANGE_in_sbitrange769 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_sbitrange773 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_identifier_in_sbitrange777 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_sbitrange781 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_sbitrange785 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_PCODEOP_in_pcodeopdef800 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifierlist_in_pcodeopdef804 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_VALUES_in_valueattach819 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifierlist_in_valueattach823 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000004000L});
	public static final BitSet FOLLOW_intblist_in_valueattach827 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_INTBLIST_in_intblist846 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_intbpart_in_intblist853 = new BitSet(new long[]{0x0000000000000008L,0x0000200008000000L,0x0000000040000400L,0x0000000000001000L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_intbpart876 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NEGATE_in_intbpart884 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_intbpart888 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_integer_in_intbpart898 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NAMES_in_nameattach912 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifierlist_in_nameattach916 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x8000000000000000L});
	public static final BitSet FOLLOW_stringoridentlist_in_nameattach920 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_VARIABLES_in_varattach935 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifierlist_in_varattach939 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000001000L});
	public static final BitSet FOLLOW_identifierlist_in_varattach943 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_macrodef_in_constructorlike957 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_constructor_in_constructorlike962 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_MACRO_in_macrodef974 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_macrodef978 = new BitSet(new long[]{0x0000000000000000L,0x0010000001000000L});
	public static final BitSet FOLLOW_arguments_in_macrodef982 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0002000000000000L});
	public static final BitSet FOLLOW_semantic_in_macrodef986 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ARGUMENTS_in_arguments1003 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_oplist_in_arguments1007 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_EMPTY_LIST_in_arguments1015 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_oplist1040 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_OP_CONSTRUCTOR_in_constructor1056 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_ctorstart_in_constructor1060 = new BitSet(new long[]{0x0000000000000000L,0x0000000080000000L});
	public static final BitSet FOLLOW_bitpattern_in_constructor1064 = new BitSet(new long[]{0x0000000000000000L,0x0000010000000000L,0x0000002000000000L});
	public static final BitSet FOLLOW_contextblock_in_constructor1068 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_ctorsemantic_in_constructor1070 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_PCODE_in_ctorsemantic1083 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_semantic_in_ctorsemantic1085 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_PCODE_in_ctorsemantic1092 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_UNIMPL_in_ctorsemantic1094 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BIT_PATTERN_in_bitpattern1113 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_bitpattern1117 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SUBTABLE_in_ctorstart1136 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_ctorstart1140 = new BitSet(new long[]{0x0000000000000000L,0x0001000000000000L});
	public static final BitSet FOLLOW_display_in_ctorstart1144 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_TABLE_in_ctorstart1153 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_display_in_ctorstart1157 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DISPLAY_in_display1176 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pieces_in_display1180 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_printpiece_in_pieces1206 = new BitSet(new long[]{0x0000000000000002L,0x0000002000000000L,0x4000080000000800L,0x0000000000001800L});
	public static final BitSet FOLLOW_identifier_in_printpiece1227 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_whitespace_in_printpiece1236 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_CONCATENATE_in_printpiece1243 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_string_in_printpiece1252 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_WHITESPACE_in_whitespace1270 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_STRING_in_string1293 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_QSTRING_in_string1306 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_BOOL_OR_in_pequation1329 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1333 = new BitSet(new long[]{0x0000000000000000L,0x004C000300000000L,0x0004010801800980L,0x0000000000001000L});
	public static final BitSet FOLLOW_pequation_in_pequation1337 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SEQUENCE_in_pequation1346 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1350 = new BitSet(new long[]{0x0000000000000000L,0x004C000300000000L,0x0004010801800980L,0x0000000000001000L});
	public static final BitSet FOLLOW_pequation_in_pequation1354 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BOOL_AND_in_pequation1363 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1367 = new BitSet(new long[]{0x0000000000000000L,0x004C000300000000L,0x0004010801800980L,0x0000000000001000L});
	public static final BitSet FOLLOW_pequation_in_pequation1371 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ELLIPSIS_in_pequation1381 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1385 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ELLIPSIS_RIGHT_in_pequation1394 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1398 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_EQUAL_in_pequation1408 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_pequation1412 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pequation1416 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NOTEQUAL_in_pequation1425 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_pequation1429 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pequation1433 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LESS_in_pequation1442 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_pequation1446 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pequation1450 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LESSEQUAL_in_pequation1459 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_pequation1463 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pequation1467 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GREAT_in_pequation1476 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_pequation1480 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pequation1484 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GREATEQUAL_in_pequation1493 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_pequation1497 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pequation1501 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_identifier_in_pequation1512 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_PARENTHESIZED_in_pequation1520 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1524 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_OR_in_pexpression21544 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21548 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21552 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_XOR_in_pexpression21561 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21565 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21569 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_AND_in_pexpression21578 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21582 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21586 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LEFT_in_pexpression21595 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21599 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21603 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_RIGHT_in_pexpression21612 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21616 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21620 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADD_in_pexpression21629 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21633 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21637 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SUB_in_pexpression21646 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21650 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21654 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_MULT_in_pexpression21663 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21667 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21671 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DIV_in_pexpression21680 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21684 = new BitSet(new long[]{0x0000000000000000L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21688 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NEGATE_in_pexpression21698 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21702 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_INVERT_in_pexpression21711 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21715 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_APPLY_in_pexpression21725 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_pexpression21729 = new BitSet(new long[]{0x0000000000000008L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_operands_in_pexpression21733 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_identifier_in_pexpression21743 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_pexpression21752 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_PARENTHESIZED_in_pexpression21760 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression21764 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression2_operands1790 = new BitSet(new long[]{0x0000000000000002L,0x0002200008C80000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_OP_CONTEXT_BLOCK_in_contextblock1806 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_statements_in_contextblock1810 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NO_CONTEXT_BLOCK_in_contextblock1818 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_SEMANTIC_in_semantic1830 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_code_block_in_semantic1834 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_statements_in_code_block1849 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NOP_in_code_block1854 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_statement_in_statements1869 = new BitSet(new long[]{0x0000000000000002L,0x0080021802800000L,0x0001200004202040L});
	public static final BitSet FOLLOW_OP_LABEL_in_label1887 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_variable_in_label1891 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SECTION_LABEL_in_section_label1910 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_variable_in_section_label1914 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_assignment_in_statement1928 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_declaration_in_statement1933 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_funcall_in_statement1938 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_build_stmt_in_statement1943 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_crossbuild_stmt_in_statement1948 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_goto_stmt_in_statement1953 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_cond_stmt_in_statement1958 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_call_stmt_in_statement1963 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_export_in_statement1968 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_return_stmt_in_statement1973 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_label_in_statement1980 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_section_label_in_statement1989 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment2003 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_lvalue_in_assignment2007 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_assignment2011 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LOCAL_in_assignment2020 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment2022 = new BitSet(new long[]{0x0000000000000000L,0x0000900010000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_lvalue_in_assignment2026 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_assignment2030 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LOCAL_in_declaration2045 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_variable_in_declaration2049 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_constant_in_declaration2053 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LOCAL_in_declaration2062 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_variable_in_declaration2066 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_bitrange_in_lvalue2097 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_DECLARATIVE_SIZE_in_lvalue2105 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_variable_in_lvalue2109 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_constant_in_lvalue2113 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_variable_in_lvalue2123 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_sizedstar_in_lvalue2132 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_BITRANGE_in_bitrange2150 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_variable_in_bitrange2154 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_constant_in_bitrange2158 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_constant_in_bitrange2162 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstar2181 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_variable_in_sizedstar2185 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_constant_in_sizedstar2189 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_sizedstar2193 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstar2202 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_variable_in_sizedstar2206 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_sizedstar2210 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstar2219 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_constant_in_sizedstar2223 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_sizedstar2227 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstar2236 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_sizedstar2240 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_expr_apply_in_funcall2256 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_BUILD_in_build_stmt2270 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_variable_in_build_stmt2274 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_CROSSBUILD_in_crossbuild_stmt2289 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_in_crossbuild_stmt2293 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_variable_in_crossbuild_stmt2297 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GOTO_in_goto_stmt2312 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_jumpdest_in_goto_stmt2316 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_SYMBOL_in_jumpdest2335 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_variable_in_jumpdest2339 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_DYNAMIC_in_jumpdest2348 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_jumpdest2352 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_ABSOLUTE_in_jumpdest2361 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_jumpdest2365 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_RELATIVE_in_jumpdest2374 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_constant_in_jumpdest2378 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_variable_in_jumpdest2382 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_LABEL_in_jumpdest2391 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_label_in_jumpdest2395 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IF_in_cond_stmt2410 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_cond_stmt2414 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000040L});
	public static final BitSet FOLLOW_goto_stmt_in_cond_stmt2418 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_CALL_in_call_stmt2431 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_jumpdest_in_call_stmt2435 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_RETURN_in_return_stmt2450 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_return_stmt2454 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_RETURN_in_return_stmt2462 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_EXPORT_in_export2476 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_export2480 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BOOL_OR_in_expr2499 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2503 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2507 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BOOL_XOR_in_expr2516 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2520 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2524 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BOOL_AND_in_expr2533 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2537 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2541 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_OR_in_expr2551 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2555 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2559 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_XOR_in_expr2568 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2572 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2576 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_AND_in_expr2585 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2589 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2593 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_EQUAL_in_expr2603 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2607 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2611 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NOTEQUAL_in_expr2620 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2624 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2628 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FEQUAL_in_expr2637 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2641 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2645 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FNOTEQUAL_in_expr2654 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2658 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2662 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LESS_in_expr2672 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2676 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2680 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GREATEQUAL_in_expr2689 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2693 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2697 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LESSEQUAL_in_expr2706 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2710 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2714 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GREAT_in_expr2723 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2727 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2731 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SLESS_in_expr2740 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2744 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2748 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SGREATEQUAL_in_expr2757 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2761 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2765 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SLESSEQUAL_in_expr2774 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2778 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2782 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SGREAT_in_expr2791 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2795 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2799 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FLESS_in_expr2808 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2812 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2816 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FGREATEQUAL_in_expr2825 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2829 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2833 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FLESSEQUAL_in_expr2842 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2846 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2850 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FGREAT_in_expr2859 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2863 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2867 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LEFT_in_expr2877 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2881 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2885 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_RIGHT_in_expr2894 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2898 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2902 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SRIGHT_in_expr2911 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2915 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2919 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADD_in_expr2929 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2933 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2937 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SUB_in_expr2946 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2950 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2954 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FADD_in_expr2963 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2967 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2971 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FSUB_in_expr2980 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr2984 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr2988 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_MULT_in_expr2998 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr3002 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr3006 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DIV_in_expr3016 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr3020 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr3024 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_REM_in_expr3033 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr3037 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr3041 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SDIV_in_expr3050 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr3054 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr3058 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SREM_in_expr3067 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr3071 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr3075 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FMULT_in_expr3084 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr3088 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr3092 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FDIV_in_expr3101 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr3105 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr3109 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NOT_in_expr3119 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr3123 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_INVERT_in_expr3132 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr3136 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NEGATE_in_expr3145 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr3149 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FNEGATE_in_expr3158 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr3162 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_sizedstar_in_expr3172 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_apply_in_expr3182 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_varnode_in_expr3191 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_bitrange_in_expr3200 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_PARENTHESIZED_in_expr3208 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr3212 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BITRANGE2_in_expr3221 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_expr3225 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_expr3229 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_APPLY_in_expr_apply3248 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifier_in_expr_apply3252 = new BitSet(new long[]{0x0000000000000008L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_operands_in_expr_apply3256 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_expr_in_expr_operands3283 = new BitSet(new long[]{0x0000000000000002L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_symbol_in_varnode3304 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_TRUNCATION_SIZE_in_varnode3312 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_symbol_in_varnode3316 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_constant_in_varnode3320 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADDRESS_OF_in_varnode3329 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_SIZING_SIZE_in_varnode3332 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_constant_in_varnode3336 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_varnode_in_varnode3341 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADDRESS_OF_in_varnode3350 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_in_varnode3354 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_identifier_in_symbol3374 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_symbol3383 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_variable3402 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_constant3421 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_QSTRING_in_qstring3439 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_identifier3462 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_identifier3474 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_HEX_CONSTANT_in_integer3492 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_DEC_CONSTANT_in_integer3505 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_BIN_CONSTANT_in_integer3518 = new BitSet(new long[]{0x0000000000000004L});
}
