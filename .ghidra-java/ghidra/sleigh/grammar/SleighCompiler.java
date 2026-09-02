package ghidra.sleigh.grammar;
// $ANTLR 3.5.2 ghidra/sleigh/grammar/SleighCompiler.g 2026-08-17 17:23:47

	import generic.stl.Pair;
	import generic.stl.VectorSTL;
	import ghidra.pcodeCPort.context.SleighError;
	import ghidra.pcodeCPort.opcodes.OpCode;
	import ghidra.pcodeCPort.semantics.*;
	import ghidra.pcodeCPort.slgh_compile.*;
	import ghidra.pcodeCPort.slghpatexpress.*;
	import ghidra.pcodeCPort.slghsymbol.*;
	import ghidra.pcodeCPort.space.AddrSpace;

	import java.math.BigInteger;
	import java.util.Stack;

	import org.antlr.runtime.*;
	import org.antlr.runtime.Token;
	import org.antlr.runtime.tree.*;


import org.antlr.runtime.*;
import org.antlr.runtime.tree.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

@SuppressWarnings("all")
public class SleighCompiler extends TreeParser {
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

	protected static class Return_scope {
		boolean noReturn;
	}
	protected Stack<Return_scope> Return_stack = new Stack<Return_scope>();

	protected static class Block_scope {
		ConstructTpl ct;
	}
	protected Stack<Block_scope> Block_stack = new Stack<Block_scope>();

	protected static class Jump_scope {
		boolean indirect;
	}
	protected Stack<Jump_scope> Jump_stack = new Stack<Jump_scope>();


	public SleighCompiler(TreeNodeStream input) {
		this(input, new RecognizerSharedState());
	}
	public SleighCompiler(TreeNodeStream input, RecognizerSharedState state) {
		super(input, state);
	}

	@Override public String[] getTokenNames() { return SleighCompiler.tokenNames; }
	@Override public String getGrammarFileName() { return "ghidra/sleigh/grammar/SleighCompiler.g"; }


		private static final BigInteger MAX_ULONG = new BigInteger("ffffffffffffffff", 16);
		private static final BigInteger MIN_SLONG = new BigInteger("-8000000000000000", 16);
		private static final BigInteger MAX_UINT = new BigInteger("ffffffff", 16);

		private ParsingEnvironment env = null;
		private SleighCompile sc = null;
		private PcodeCompile pcode = null;

		private void reportError(Location loc, String msg) {
			if (pcode != null) {
		    	pcode.reportError(loc, msg);
		    }
		    else {
		    	sc.reportError(loc, msg);
		    }
		}

		private void reportWarning(Location loc, String msg) {
			if (pcode != null) {
		    	pcode.reportWarning(loc, msg);
		    }
		    else {
		    	sc.reportWarning(loc, msg);
		    }
		}

		private void check(RadixBigInteger rbi) {
			if (rbi.bitLength() > 64) {
				reportError(rbi.location, "Integer representation exceeds Java long (" + rbi + ")");
			}
		}

		private long toSLong(RadixBigInteger bi) {
			try {
				return bi.longValueExact();
			}
			catch (ArithmeticException e) {
				reportError(bi.location, "Integer cannot be represented as signed long: " + bi);
				return bi.longValue();
			}
		}

		private long toULong(RadixBigInteger bi) {
			if (bi.compareTo(MAX_ULONG) > 0 || bi.signum() < 0) {
				reportError(bi.location, "Integer cannot be represented as unsigned long: " + bi);
			}
			return bi.longValue();
		}

		private long toLong(RadixBigInteger bi) {
			if (bi.compareTo(MAX_ULONG) > 0 || bi.compareTo(MIN_SLONG) < 0) {
				reportError(bi.location, "Integer cannot be represented as long: " + bi);
			}
			return bi.longValue();
		}

		private int toUInt(RadixBigInteger bi) {
			if (bi.compareTo(MAX_UINT) > 0 || bi.signum() < 0) {
				reportError(bi.location, "Integer cannot be represented as unsigned int: " + bi);
			}
			return bi.intValue();
		}

		private void redefinedError(SleighSymbol sym, Tree t, String what) {
		    String msg = "symbol '" + sym.getName() + "' (from " + sym.getLocation() + ") redefined as " + what;
		    reportError(find(t), msg);
		}

		private void wildcardError(Tree t, String what) {
		    String msg = "wildcard (_) not allowed in " + what;
		    reportError(find(t), msg);
		}

		private void wrongSymbolTypeError(SleighSymbol sym, Location where, String type, String purpose) {
		    String msg = sym.getType() + " '" + sym + "' (defined at " + sym.getLocation() + ") is wrong type (should be " + type + ") in " + purpose;
		    reportError(where, msg);
		}

		private void undeclaredSymbolError(SleighSymbol sym, Location where, String purpose) {
		    String msg = "'" + sym + "' (used in " + purpose + ") is not declared in the pattern list";
		    reportError(where, msg);
		}

		private void unknownSymbolError(String text, Location loc, String type, String purpose) {
		    String msg = "unknown " + type + " '" + text + "' in " + purpose;
		    reportError(loc, msg);
		}

		private void invalidDynamicTargetError(Location loc, String purpose) {
		    String msg = "invalid dynamic target used in " + purpose;
		    reportError(loc, msg);
		}

		private Location find(Tree t) {
		    return env.getLocator().getLocation(t.getLine());
		}
		
		private SubtableSymbol findOrNewTable(Location loc, String name) {
			SleighSymbol sym = sc.findSymbol(name);
			if (sym == null) {
				SubtableSymbol ss = sc.newTable(loc, name);
				return ss;
			} else if(sym.getType() != symbol_type.subtable_symbol) {
				wrongSymbolTypeError(sym, loc, "subtable", "subconstructor");
				return null;
			} else {
				return (SubtableSymbol) sym;
			}
		}

		public String getErrorMessage(RecognitionException e, String[] tokenNames) {
		    return env.getParserErrorMessage(e, tokenNames);
		}

		public String getTokenErrorDisplay(Token t) {
		    return env.getTokenErrorDisplay(t);
		}

		public String getErrorHeader(RecognitionException e) {
		    return env.getErrorHeader(e);
		}

		void bail(String msg) {
		    throw new BailoutException(msg);
		}



	// $ANTLR start "root"
	// ghidra/sleigh/grammar/SleighCompiler.g:167:1: root[ParsingEnvironment pe, SleighCompile sc] returns [int errors] : endiandef ( definition | constructorlike )* ;
	public final int root(ParsingEnvironment pe, SleighCompile sc) throws RecognitionException {
		int errors = 0;



				this.env = pe;
				this.sc = sc;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:175:2: ( endiandef ( definition | constructorlike )* )
			// ghidra/sleigh/grammar/SleighCompiler.g:175:4: endiandef ( definition | constructorlike )*
			{
			pushFollow(FOLLOW_endiandef_in_root80);
			endiandef();
			state._fsp--;

			// ghidra/sleigh/grammar/SleighCompiler.g:176:3: ( definition | constructorlike )*
			loop1:
			while (true) {
				int alt1=3;
				int LA1_0 = input.LA(1);
				if ( (LA1_0==OP_ALIGNMENT||LA1_0==OP_BITRANGES||LA1_0==OP_CONTEXT||LA1_0==OP_NAMES||LA1_0==OP_PCODEOP||LA1_0==OP_SPACE||(LA1_0 >= OP_TOKEN && LA1_0 <= OP_TOKEN_ENDIAN)||(LA1_0 >= OP_VALUES && LA1_0 <= OP_VARNODE)) ) {
					alt1=1;
				}
				else if ( (LA1_0==OP_CONSTRUCTOR||LA1_0==OP_MACRO||LA1_0==OP_WITH) ) {
					alt1=2;
				}

				switch (alt1) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:176:5: definition
					{
					pushFollow(FOLLOW_definition_in_root86);
					definition();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:177:5: constructorlike
					{
					pushFollow(FOLLOW_constructorlike_in_root92);
					constructorlike();
					state._fsp--;

					}
					break;

				default :
					break loop1;
				}
			}

			}


					errors = env.getLexingErrors() + env.getParsingErrors();
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return errors;
	}
	// $ANTLR end "root"



	// $ANTLR start "endiandef"
	// ghidra/sleigh/grammar/SleighCompiler.g:181:1: endiandef : ^( OP_ENDIAN s= endian ) ;
	public final void endiandef() throws RecognitionException {
		int s =0;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:182:2: ( ^( OP_ENDIAN s= endian ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:182:4: ^( OP_ENDIAN s= endian )
			{
			match(input,OP_ENDIAN,FOLLOW_OP_ENDIAN_in_endiandef109); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_endian_in_endiandef113);
			s=endian();
			state._fsp--;

			match(input, Token.UP, null); 

			 sc.setEndian(s); 
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



	// $ANTLR start "endian"
	// ghidra/sleigh/grammar/SleighCompiler.g:185:1: endian returns [int value] : ( OP_BIG | OP_LITTLE );
	public final int endian() throws RecognitionException {
		int value = 0;


		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:186:2: ( OP_BIG | OP_LITTLE )
			int alt2=2;
			int LA2_0 = input.LA(1);
			if ( (LA2_0==OP_BIG) ) {
				alt2=1;
			}
			else if ( (LA2_0==OP_LITTLE) ) {
				alt2=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 2, 0, input);
				throw nvae;
			}

			switch (alt2) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:186:4: OP_BIG
					{
					match(input,OP_BIG,FOLLOW_OP_BIG_in_endian131); 
					 value = 1; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:187:4: OP_LITTLE
					{
					match(input,OP_LITTLE,FOLLOW_OP_LITTLE_in_endian141); 
					 value = 0; 
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
	// $ANTLR end "endian"



	// $ANTLR start "definition"
	// ghidra/sleigh/grammar/SleighCompiler.g:190:1: definition : ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach ) ;
	public final void definition() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:191:2: ( ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:191:4: ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach )
			{
			// ghidra/sleigh/grammar/SleighCompiler.g:191:4: ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach )
			int alt3=10;
			switch ( input.LA(1) ) {
			case OP_ALIGNMENT:
				{
				alt3=1;
				}
				break;
			case OP_TOKEN:
			case OP_TOKEN_ENDIAN:
				{
				alt3=2;
				}
				break;
			case OP_CONTEXT:
				{
				alt3=3;
				}
				break;
			case OP_SPACE:
				{
				alt3=4;
				}
				break;
			case OP_VARNODE:
				{
				alt3=5;
				}
				break;
			case OP_BITRANGES:
				{
				alt3=6;
				}
				break;
			case OP_PCODEOP:
				{
				alt3=7;
				}
				break;
			case OP_VALUES:
				{
				alt3=8;
				}
				break;
			case OP_NAMES:
				{
				alt3=9;
				}
				break;
			case OP_VARIABLES:
				{
				alt3=10;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 3, 0, input);
				throw nvae;
			}
			switch (alt3) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:191:5: aligndef
					{
					pushFollow(FOLLOW_aligndef_in_definition155);
					aligndef();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:192:4: tokendef
					{
					pushFollow(FOLLOW_tokendef_in_definition160);
					tokendef();
					state._fsp--;

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:193:4: contextdef
					{
					pushFollow(FOLLOW_contextdef_in_definition165);
					contextdef();
					state._fsp--;

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:194:4: spacedef
					{
					pushFollow(FOLLOW_spacedef_in_definition170);
					spacedef();
					state._fsp--;

					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:195:4: varnodedef
					{
					pushFollow(FOLLOW_varnodedef_in_definition175);
					varnodedef();
					state._fsp--;

					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:196:4: bitrangedef
					{
					pushFollow(FOLLOW_bitrangedef_in_definition180);
					bitrangedef();
					state._fsp--;

					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:197:4: pcodeopdef
					{
					pushFollow(FOLLOW_pcodeopdef_in_definition185);
					pcodeopdef();
					state._fsp--;

					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighCompiler.g:198:4: valueattach
					{
					pushFollow(FOLLOW_valueattach_in_definition190);
					valueattach();
					state._fsp--;

					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighCompiler.g:199:4: nameattach
					{
					pushFollow(FOLLOW_nameattach_in_definition195);
					nameattach();
					state._fsp--;

					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighCompiler.g:200:4: varattach
					{
					pushFollow(FOLLOW_varattach_in_definition200);
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
	// ghidra/sleigh/grammar/SleighCompiler.g:204:1: aligndef : ^( OP_ALIGNMENT i= integer ) ;
	public final void aligndef() throws RecognitionException {
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:205:2: ( ^( OP_ALIGNMENT i= integer ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:205:4: ^( OP_ALIGNMENT i= integer )
			{
			match(input,OP_ALIGNMENT,FOLLOW_OP_ALIGNMENT_in_aligndef215); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_integer_in_aligndef219);
			i=integer();
			state._fsp--;

			match(input, Token.UP, null); 

			 sc.setAlignment(toUInt(i)); 
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


	protected static class tokendef_scope {
		TokenSymbol tokenSymbol;
	}
	protected Stack<tokendef_scope> tokendef_stack = new Stack<tokendef_scope>();


	// $ANTLR start "tokendef"
	// ghidra/sleigh/grammar/SleighCompiler.g:208:1: tokendef : ( ^( OP_TOKEN n= specific_identifier[\"token definition\"] i= integer fielddefs ) | ^( OP_TOKEN_ENDIAN n= specific_identifier[\"token definition\"] i= integer s= endian fielddefs ) );
	public final void tokendef() throws RecognitionException {
		tokendef_stack.push(new tokendef_scope());
		Tree n =null;
		RadixBigInteger i =null;
		int s =0;


				tokendef_stack.peek().tokenSymbol = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:215:2: ( ^( OP_TOKEN n= specific_identifier[\"token definition\"] i= integer fielddefs ) | ^( OP_TOKEN_ENDIAN n= specific_identifier[\"token definition\"] i= integer s= endian fielddefs ) )
			int alt4=2;
			int LA4_0 = input.LA(1);
			if ( (LA4_0==OP_TOKEN) ) {
				alt4=1;
			}
			else if ( (LA4_0==OP_TOKEN_ENDIAN) ) {
				alt4=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 4, 0, input);
				throw nvae;
			}

			switch (alt4) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:215:4: ^( OP_TOKEN n= specific_identifier[\"token definition\"] i= integer fielddefs )
					{
					match(input,OP_TOKEN,FOLLOW_OP_TOKEN_in_tokendef245); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_specific_identifier_in_tokendef249);
					n=specific_identifier("token definition");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_tokendef254);
					i=integer();
					state._fsp--;


								if (n != null) {
									SleighSymbol sym = sc.findSymbol(n.getText());
									if (sym != null) {
										redefinedError(sym, n, "token");
									} else {
										tokendef_stack.peek().tokenSymbol = sc.defineToken(find(n), n.getText(), toLong(i), 0);
									}
								}
							
					pushFollow(FOLLOW_fielddefs_in_tokendef258);
					fielddefs();
					state._fsp--;

					match(input, Token.UP, null); 

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:225:6: ^( OP_TOKEN_ENDIAN n= specific_identifier[\"token definition\"] i= integer s= endian fielddefs )
					{
					match(input,OP_TOKEN_ENDIAN,FOLLOW_OP_TOKEN_ENDIAN_in_tokendef267); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_specific_identifier_in_tokendef271);
					n=specific_identifier("token definition");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_tokendef276);
					i=integer();
					state._fsp--;

					pushFollow(FOLLOW_endian_in_tokendef280);
					s=endian();
					state._fsp--;


								if (n != null) {
								    SleighSymbol sym = sc.findSymbol(n.getText());
								    if (sym != null) {
								        redefinedError(sym, n, "token");
								    } else {
								        tokendef_stack.peek().tokenSymbol = sc.defineToken(find(n), n.getText(), toLong(i), s ==0 ? -1 : 1);
								    }
								}
						    
					pushFollow(FOLLOW_fielddefs_in_tokendef284);
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
			tokendef_stack.pop();
		}
	}
	// $ANTLR end "tokendef"



	// $ANTLR start "fielddefs"
	// ghidra/sleigh/grammar/SleighCompiler.g:237:1: fielddefs : ^( OP_FIELDDEFS ( fielddef )* ) ;
	public final void fielddefs() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:238:2: ( ^( OP_FIELDDEFS ( fielddef )* ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:238:4: ^( OP_FIELDDEFS ( fielddef )* )
			{
			match(input,OP_FIELDDEFS,FOLLOW_OP_FIELDDEFS_in_fielddefs297); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				// ghidra/sleigh/grammar/SleighCompiler.g:238:19: ( fielddef )*
				loop5:
				while (true) {
					int alt5=2;
					int LA5_0 = input.LA(1);
					if ( (LA5_0==OP_FIELDDEF) ) {
						alt5=1;
					}

					switch (alt5) {
					case 1 :
						// ghidra/sleigh/grammar/SleighCompiler.g:238:19: fielddef
						{
						pushFollow(FOLLOW_fielddef_in_fielddefs299);
						fielddef();
						state._fsp--;

						}
						break;

					default :
						break loop5;
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
	}
	// $ANTLR end "fielddefs"


	protected static class fielddef_scope {
		FieldQuality fieldQuality;
	}
	protected Stack<fielddef_scope> fielddef_stack = new Stack<fielddef_scope>();


	// $ANTLR start "fielddef"
	// ghidra/sleigh/grammar/SleighCompiler.g:241:1: fielddef : ^(t= OP_FIELDDEF n= unbound_identifier[\"field\"] s= integer e= integer fieldmods ) ;
	public final void fielddef() throws RecognitionException {
		fielddef_stack.push(new fielddef_scope());
		CommonTree t=null;
		Tree n =null;
		RadixBigInteger s =null;
		RadixBigInteger e =null;


				fielddef_stack.peek().fieldQuality = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:248:2: ( ^(t= OP_FIELDDEF n= unbound_identifier[\"field\"] s= integer e= integer fieldmods ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:248:4: ^(t= OP_FIELDDEF n= unbound_identifier[\"field\"] s= integer e= integer fieldmods )
			{
			t=(CommonTree)match(input,OP_FIELDDEF,FOLLOW_OP_FIELDDEF_in_fielddef325); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_unbound_identifier_in_fielddef329);
			n=unbound_identifier("field");
			state._fsp--;

			pushFollow(FOLLOW_integer_in_fielddef334);
			s=integer();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_fielddef338);
			e=integer();
			state._fsp--;


						if (n != null) {
			                fielddef_stack.peek().fieldQuality = new FieldQuality(n.getText(), find(t), toULong(s), toULong(e));
						}
					
			pushFollow(FOLLOW_fieldmods_in_fielddef342);
			fieldmods();
			state._fsp--;

			match(input, Token.UP, null); 


						if (fielddef_stack.size() > 0 && fielddef_stack.peek().fieldQuality != null) {
							if (tokendef_stack.size() > 0 && tokendef_stack.peek().tokenSymbol != null) {
								sc.addTokenField(find(n), tokendef_stack.peek().tokenSymbol, fielddef_stack.peek().fieldQuality);
							} else if (contextdef_stack.size() > 0 && contextdef_stack.peek().varnode != null) {
								if (!sc.addContextField(find(n), contextdef_stack.peek().varnode, fielddef_stack.peek().fieldQuality)) {
									reportError(find(t), "all context definitions must come before constructors");
								}
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
			fielddef_stack.pop();
		}
	}
	// $ANTLR end "fielddef"



	// $ANTLR start "fieldmods"
	// ghidra/sleigh/grammar/SleighCompiler.g:265:1: fieldmods : ( ^( OP_FIELD_MODS ( fieldmod )+ ) | OP_NO_FIELD_MOD );
	public final void fieldmods() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:266:2: ( ^( OP_FIELD_MODS ( fieldmod )+ ) | OP_NO_FIELD_MOD )
			int alt7=2;
			int LA7_0 = input.LA(1);
			if ( (LA7_0==OP_FIELD_MODS) ) {
				alt7=1;
			}
			else if ( (LA7_0==OP_NO_FIELD_MOD) ) {
				alt7=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 7, 0, input);
				throw nvae;
			}

			switch (alt7) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:266:4: ^( OP_FIELD_MODS ( fieldmod )+ )
					{
					match(input,OP_FIELD_MODS,FOLLOW_OP_FIELD_MODS_in_fieldmods357); 
					match(input, Token.DOWN, null); 
					// ghidra/sleigh/grammar/SleighCompiler.g:266:20: ( fieldmod )+
					int cnt6=0;
					loop6:
					while (true) {
						int alt6=2;
						int LA6_0 = input.LA(1);
						if ( (LA6_0==OP_DEC||LA6_0==OP_HEX||LA6_0==OP_NOFLOW||LA6_0==OP_SIGNED) ) {
							alt6=1;
						}

						switch (alt6) {
						case 1 :
							// ghidra/sleigh/grammar/SleighCompiler.g:266:20: fieldmod
							{
							pushFollow(FOLLOW_fieldmod_in_fieldmods359);
							fieldmod();
							state._fsp--;

							}
							break;

						default :
							if ( cnt6 >= 1 ) break loop6;
							EarlyExitException eee = new EarlyExitException(6, input);
							throw eee;
						}
						cnt6++;
					}

					match(input, Token.UP, null); 

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:267:4: OP_NO_FIELD_MOD
					{
					match(input,OP_NO_FIELD_MOD,FOLLOW_OP_NO_FIELD_MOD_in_fieldmods366); 
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
	// $ANTLR end "fieldmods"



	// $ANTLR start "fieldmod"
	// ghidra/sleigh/grammar/SleighCompiler.g:270:1: fieldmod : ( OP_SIGNED | OP_NOFLOW | OP_HEX | OP_DEC );
	public final void fieldmod() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:271:5: ( OP_SIGNED | OP_NOFLOW | OP_HEX | OP_DEC )
			int alt8=4;
			switch ( input.LA(1) ) {
			case OP_SIGNED:
				{
				alt8=1;
				}
				break;
			case OP_NOFLOW:
				{
				alt8=2;
				}
				break;
			case OP_HEX:
				{
				alt8=3;
				}
				break;
			case OP_DEC:
				{
				alt8=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 8, 0, input);
				throw nvae;
			}
			switch (alt8) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:271:9: OP_SIGNED
					{
					match(input,OP_SIGNED,FOLLOW_OP_SIGNED_in_fieldmod382); 
					 if (fielddef_stack.peek().fieldQuality != null) fielddef_stack.peek().fieldQuality.signext = true; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:272:9: OP_NOFLOW
					{
					match(input,OP_NOFLOW,FOLLOW_OP_NOFLOW_in_fieldmod394); 
					 if (fielddef_stack.peek().fieldQuality != null) fielddef_stack.peek().fieldQuality.flow = false; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:273:9: OP_HEX
					{
					match(input,OP_HEX,FOLLOW_OP_HEX_in_fieldmod406); 
					 if (fielddef_stack.peek().fieldQuality != null) fielddef_stack.peek().fieldQuality.hex = true; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:274:9: OP_DEC
					{
					match(input,OP_DEC,FOLLOW_OP_DEC_in_fieldmod418); 
					 if (fielddef_stack.peek().fieldQuality != null) fielddef_stack.peek().fieldQuality.hex = false; 
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
	// $ANTLR end "fieldmod"



	// $ANTLR start "specific_identifier"
	// ghidra/sleigh/grammar/SleighCompiler.g:277:1: specific_identifier[String purpose] returns [Tree value] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final Tree specific_identifier(String purpose) throws RecognitionException {
		Tree value = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:278:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt9=2;
			int LA9_0 = input.LA(1);
			if ( (LA9_0==OP_IDENTIFIER) ) {
				alt9=1;
			}
			else if ( (LA9_0==OP_WILDCARD) ) {
				alt9=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 9, 0, input);
				throw nvae;
			}

			switch (alt9) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:278:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_specific_identifier440); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = s; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:279:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_specific_identifier454); 

								wildcardError(t, purpose);
								value = null;
							
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
	// $ANTLR end "specific_identifier"



	// $ANTLR start "unbound_identifier"
	// ghidra/sleigh/grammar/SleighCompiler.g:285:1: unbound_identifier[String purpose] returns [Tree value] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final Tree unbound_identifier(String purpose) throws RecognitionException {
		Tree value = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:286:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt10=2;
			int LA10_0 = input.LA(1);
			if ( (LA10_0==OP_IDENTIFIER) ) {
				alt10=1;
			}
			else if ( (LA10_0==OP_WILDCARD) ) {
				alt10=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 10, 0, input);
				throw nvae;
			}

			switch (alt10) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:286:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_unbound_identifier473); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


						        // use PcodeCompile for symbol table while parsing pcode
					        	SleighSymbol sym = pcode != null ? pcode.findSymbol(s.getText()) : sc.findSymbol(s.getText());
								if (sym != null) {
									redefinedError(sym, s, purpose);
									value = null;
								} else {
									value = s;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:296:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_unbound_identifier487); 

								wildcardError(t, purpose);
								value = null;
							
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
	// $ANTLR end "unbound_identifier"



	// $ANTLR start "varnode_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:302:1: varnode_symbol[String purpose, boolean noWildcards] returns [VarnodeSymbol symbol] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final VarnodeSymbol varnode_symbol(String purpose, boolean noWildcards) throws RecognitionException {
		VarnodeSymbol symbol = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:303:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt11=2;
			int LA11_0 = input.LA(1);
			if ( (LA11_0==OP_IDENTIFIER) ) {
				alt11=1;
			}
			else if ( (LA11_0==OP_WILDCARD) ) {
				alt11=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 11, 0, input);
				throw nvae;
			}

			switch (alt11) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:303:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_varnode_symbol506); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "varnode", purpose);
								} else if(sym.getType() != symbol_type.varnode_symbol) {
									wrongSymbolTypeError(sym, find(s), "varnode", purpose);
								} else {
									symbol = (VarnodeSymbol) sym;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:313:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_varnode_symbol520); 

								if (noWildcards) {
									wildcardError(t, purpose);
								}
								symbol = null;
							
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
		return symbol;
	}
	// $ANTLR end "varnode_symbol"



	// $ANTLR start "value_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:321:1: value_symbol[String purpose] returns [Pair<ValueSymbol,Location> symbol] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final Pair<ValueSymbol,Location> value_symbol(String purpose) throws RecognitionException {
		Pair<ValueSymbol,Location> symbol = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:322:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt12=2;
			int LA12_0 = input.LA(1);
			if ( (LA12_0==OP_IDENTIFIER) ) {
				alt12=1;
			}
			else if ( (LA12_0==OP_WILDCARD) ) {
				alt12=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 12, 0, input);
				throw nvae;
			}

			switch (alt12) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:322:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_value_symbol539); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "value or context", purpose);
								} else if(sym.getType() == symbol_type.value_symbol
										|| sym.getType() == symbol_type.context_symbol) {
									symbol = new Pair<ValueSymbol,Location>((ValueSymbol) sym, find(s));
								} else {
									wrongSymbolTypeError(sym, find(s), "value or context", purpose);
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:333:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_value_symbol553); 

								wildcardError(t, purpose);
								symbol = null;
							
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
		return symbol;
	}
	// $ANTLR end "value_symbol"



	// $ANTLR start "operand_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:339:1: operand_symbol[String purpose] returns [OperandSymbol symbol] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final OperandSymbol operand_symbol(String purpose) throws RecognitionException {
		OperandSymbol symbol = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:340:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt13=2;
			int LA13_0 = input.LA(1);
			if ( (LA13_0==OP_IDENTIFIER) ) {
				alt13=1;
			}
			else if ( (LA13_0==OP_WILDCARD) ) {
				alt13=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 13, 0, input);
				throw nvae;
			}

			switch (alt13) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:340:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_operand_symbol572); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = pcode.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "operand", purpose);
								} else if(sym.getType() != symbol_type.operand_symbol) {
									wrongSymbolTypeError(sym, find(s), "operand", purpose);
								} else {
									symbol = (OperandSymbol) sym;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:350:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_operand_symbol586); 

								wildcardError(t, purpose);
								symbol = null;
							
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
		return symbol;
	}
	// $ANTLR end "operand_symbol"



	// $ANTLR start "space_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:356:1: space_symbol[String purpose] returns [SpaceSymbol symbol] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final SpaceSymbol space_symbol(String purpose) throws RecognitionException {
		SpaceSymbol symbol = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:357:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt14=2;
			int LA14_0 = input.LA(1);
			if ( (LA14_0==OP_IDENTIFIER) ) {
				alt14=1;
			}
			else if ( (LA14_0==OP_WILDCARD) ) {
				alt14=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 14, 0, input);
				throw nvae;
			}

			switch (alt14) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:357:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_space_symbol605); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								// use PcodeCompile for symbol table while parsing pcode
					        	SleighSymbol sym = pcode != null ? pcode.findSymbol(s.getText()) : sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "space", purpose);
								} else if(sym.getType() != symbol_type.space_symbol) {
									wrongSymbolTypeError(sym, find(s), "space", purpose);
								} else {
									symbol = (SpaceSymbol) sym;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:368:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_space_symbol619); 

								wildcardError(t, purpose);
								symbol = null;
							
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
		return symbol;
	}
	// $ANTLR end "space_symbol"



	// $ANTLR start "specific_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:374:1: specific_symbol[String purpose] returns [SpecificSymbol symbol] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final SpecificSymbol specific_symbol(String purpose) throws RecognitionException {
		SpecificSymbol symbol = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:375:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt15=2;
			int LA15_0 = input.LA(1);
			if ( (LA15_0==OP_IDENTIFIER) ) {
				alt15=1;
			}
			else if ( (LA15_0==OP_WILDCARD) ) {
				alt15=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 15, 0, input);
				throw nvae;
			}

			switch (alt15) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:375:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_specific_symbol638); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = pcode.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "start, end, next2, operand, epsilon, or varnode", purpose);
								} else if(sym.getType() != symbol_type.start_symbol
										&& sym.getType() != symbol_type.end_symbol
										&& sym.getType() != symbol_type.next2_symbol
										&& sym.getType() != symbol_type.flowdest_symbol
										&& sym.getType() != symbol_type.flowref_symbol
										&& sym.getType() != symbol_type.operand_symbol
										&& sym.getType() != symbol_type.epsilon_symbol
										&& sym.getType() != symbol_type.varnode_symbol) {
									undeclaredSymbolError(sym, find(s), purpose);
								} else {
									symbol = (SpecificSymbol) sym;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:392:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_specific_symbol652); 

								wildcardError(t, purpose);
								symbol = null;
							
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
		return symbol;
	}
	// $ANTLR end "specific_symbol"



	// $ANTLR start "family_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:398:1: family_symbol[String purpose] returns [FamilySymbol symbol] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final FamilySymbol family_symbol(String purpose) throws RecognitionException {
		FamilySymbol symbol = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:399:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt16=2;
			int LA16_0 = input.LA(1);
			if ( (LA16_0==OP_IDENTIFIER) ) {
				alt16=1;
			}
			else if ( (LA16_0==OP_WILDCARD) ) {
				alt16=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 16, 0, input);
				throw nvae;
			}

			switch (alt16) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:399:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_family_symbol671); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "family", purpose);
								} else if(sym.getType() != symbol_type.value_symbol
										&& sym.getType() != symbol_type.valuemap_symbol
										&& sym.getType() != symbol_type.context_symbol
										&& sym.getType() != symbol_type.name_symbol
										&& sym.getType() != symbol_type.varnodelist_symbol) {
									wrongSymbolTypeError(sym, find(s), "family", purpose);
								} else {
									symbol = (FamilySymbol) sym;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:413:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_family_symbol685); 

								wildcardError(t, purpose);
								symbol = null;
							
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
		return symbol;
	}
	// $ANTLR end "family_symbol"


	protected static class contextdef_scope {
		VarnodeSymbol varnode;
	}
	protected Stack<contextdef_scope> contextdef_stack = new Stack<contextdef_scope>();


	// $ANTLR start "contextdef"
	// ghidra/sleigh/grammar/SleighCompiler.g:419:1: contextdef : ^( OP_CONTEXT s= varnode_symbol[\"context definition\", true] fielddefs ) ;
	public final void contextdef() throws RecognitionException {
		contextdef_stack.push(new contextdef_scope());
		VarnodeSymbol s =null;


				contextdef_stack.peek().varnode = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:426:2: ( ^( OP_CONTEXT s= varnode_symbol[\"context definition\", true] fielddefs ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:426:4: ^( OP_CONTEXT s= varnode_symbol[\"context definition\", true] fielddefs )
			{
			match(input,OP_CONTEXT,FOLLOW_OP_CONTEXT_in_contextdef710); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_varnode_symbol_in_contextdef714);
			s=varnode_symbol("context definition", true);
			state._fsp--;


						if (s != null) {
							contextdef_stack.peek().varnode = s;
						}
					
			pushFollow(FOLLOW_fielddefs_in_contextdef719);
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
			contextdef_stack.pop();
		}
	}
	// $ANTLR end "contextdef"


	protected static class spacedef_scope {
		SpaceQuality quality;
	}
	protected Stack<spacedef_scope> spacedef_stack = new Stack<spacedef_scope>();


	// $ANTLR start "spacedef"
	// ghidra/sleigh/grammar/SleighCompiler.g:433:1: spacedef : ^( OP_SPACE n= unbound_identifier[\"space\"] s= spacemods ) ;
	public final void spacedef() throws RecognitionException {
		spacedef_stack.push(new spacedef_scope());
		Tree n =null;


				spacedef_stack.peek().quality = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:440:2: ( ^( OP_SPACE n= unbound_identifier[\"space\"] s= spacemods ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:440:4: ^( OP_SPACE n= unbound_identifier[\"space\"] s= spacemods )
			{
			match(input,OP_SPACE,FOLLOW_OP_SPACE_in_spacedef743); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_unbound_identifier_in_spacedef747);
			n=unbound_identifier("space");
			state._fsp--;


						String name = "<parse error>";
						if (n != null) {
							name = n.getText();
						}
						spacedef_stack.peek().quality = new SpaceQuality(name);
					
			pushFollow(FOLLOW_spacemods_in_spacedef754);
			spacemods();
			state._fsp--;

			match(input, Token.UP, null); 


						if (n != null) {
							sc.newSpace(find(n), spacedef_stack.peek().quality);
						}
					
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			spacedef_stack.pop();
		}
	}
	// $ANTLR end "spacedef"



	// $ANTLR start "spacemods"
	// ghidra/sleigh/grammar/SleighCompiler.g:453:1: spacemods : ^( OP_SPACEMODS ( spacemod )* ) ;
	public final void spacemods() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:454:2: ( ^( OP_SPACEMODS ( spacemod )* ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:454:4: ^( OP_SPACEMODS ( spacemod )* )
			{
			match(input,OP_SPACEMODS,FOLLOW_OP_SPACEMODS_in_spacemods769); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				// ghidra/sleigh/grammar/SleighCompiler.g:454:19: ( spacemod )*
				loop17:
				while (true) {
					int alt17=2;
					int LA17_0 = input.LA(1);
					if ( (LA17_0==OP_DEFAULT||LA17_0==OP_SIZE||LA17_0==OP_TYPE||LA17_0==OP_WORDSIZE) ) {
						alt17=1;
					}

					switch (alt17) {
					case 1 :
						// ghidra/sleigh/grammar/SleighCompiler.g:454:19: spacemod
						{
						pushFollow(FOLLOW_spacemod_in_spacemods771);
						spacemod();
						state._fsp--;

						}
						break;

					default :
						break loop17;
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
	}
	// $ANTLR end "spacemods"



	// $ANTLR start "spacemod"
	// ghidra/sleigh/grammar/SleighCompiler.g:457:1: spacemod : ( typemod | sizemod | wordsizemod | OP_DEFAULT );
	public final void spacemod() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:458:2: ( typemod | sizemod | wordsizemod | OP_DEFAULT )
			int alt18=4;
			switch ( input.LA(1) ) {
			case OP_TYPE:
				{
				alt18=1;
				}
				break;
			case OP_SIZE:
				{
				alt18=2;
				}
				break;
			case OP_WORDSIZE:
				{
				alt18=3;
				}
				break;
			case OP_DEFAULT:
				{
				alt18=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 18, 0, input);
				throw nvae;
			}
			switch (alt18) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:458:4: typemod
					{
					pushFollow(FOLLOW_typemod_in_spacemod784);
					typemod();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:459:4: sizemod
					{
					pushFollow(FOLLOW_sizemod_in_spacemod789);
					sizemod();
					state._fsp--;

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:460:4: wordsizemod
					{
					pushFollow(FOLLOW_wordsizemod_in_spacemod794);
					wordsizemod();
					state._fsp--;

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:461:4: OP_DEFAULT
					{
					match(input,OP_DEFAULT,FOLLOW_OP_DEFAULT_in_spacemod799); 
					 spacedef_stack.peek().quality.isdefault = true; 
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
	// $ANTLR end "spacemod"



	// $ANTLR start "typemod"
	// ghidra/sleigh/grammar/SleighCompiler.g:464:1: typemod : ^( OP_TYPE n= specific_identifier[\"space type qualifier\"] ) ;
	public final void typemod() throws RecognitionException {
		Tree n =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:465:2: ( ^( OP_TYPE n= specific_identifier[\"space type qualifier\"] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:465:4: ^( OP_TYPE n= specific_identifier[\"space type qualifier\"] )
			{
			match(input,OP_TYPE,FOLLOW_OP_TYPE_in_typemod813); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_specific_identifier_in_typemod817);
			n=specific_identifier("space type qualifier");
			state._fsp--;

			match(input, Token.UP, null); 


						if (n != null) {
							String typeName = n.getText();
							try {
								space_class type = space_class.valueOf(typeName);
								spacedef_stack.peek().quality.type = type;
							} catch(IllegalArgumentException e) {
								reportError(find(n), "invalid space type '" + typeName + "'");
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
	// $ANTLR end "typemod"



	// $ANTLR start "sizemod"
	// ghidra/sleigh/grammar/SleighCompiler.g:478:1: sizemod : ^( OP_SIZE i= integer ) ;
	public final void sizemod() throws RecognitionException {
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:479:2: ( ^( OP_SIZE i= integer ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:479:4: ^( OP_SIZE i= integer )
			{
			match(input,OP_SIZE,FOLLOW_OP_SIZE_in_sizemod833); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_integer_in_sizemod837);
			i=integer();
			state._fsp--;

			match(input, Token.UP, null); 


						spacedef_stack.peek().quality.size = toUInt(i);
					
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
	// $ANTLR end "sizemod"



	// $ANTLR start "wordsizemod"
	// ghidra/sleigh/grammar/SleighCompiler.g:484:1: wordsizemod : ^( OP_WORDSIZE i= integer ) ;
	public final void wordsizemod() throws RecognitionException {
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:485:2: ( ^( OP_WORDSIZE i= integer ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:485:4: ^( OP_WORDSIZE i= integer )
			{
			match(input,OP_WORDSIZE,FOLLOW_OP_WORDSIZE_in_wordsizemod852); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_integer_in_wordsizemod856);
			i=integer();
			state._fsp--;

			match(input, Token.UP, null); 


						spacedef_stack.peek().quality.wordsize = toUInt(i);
					
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
	// $ANTLR end "wordsizemod"



	// $ANTLR start "varnodedef"
	// ghidra/sleigh/grammar/SleighCompiler.g:490:1: varnodedef : ^( OP_VARNODE s= space_symbol[\"varnode definition\"] offset= integer size= integer l= identifierlist ) ;
	public final void varnodedef() throws RecognitionException {
		SpaceSymbol s =null;
		RadixBigInteger offset =null;
		RadixBigInteger size =null;
		Pair<VectorSTL<String>,VectorSTL<Location>> l =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:491:2: ( ^( OP_VARNODE s= space_symbol[\"varnode definition\"] offset= integer size= integer l= identifierlist ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:491:4: ^( OP_VARNODE s= space_symbol[\"varnode definition\"] offset= integer size= integer l= identifierlist )
			{
			match(input,OP_VARNODE,FOLLOW_OP_VARNODE_in_varnodedef871); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_space_symbol_in_varnodedef875);
			s=space_symbol("varnode definition");
			state._fsp--;

			pushFollow(FOLLOW_integer_in_varnodedef880);
			offset=integer();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_varnodedef884);
			size=integer();
			state._fsp--;

			pushFollow(FOLLOW_identifierlist_in_varnodedef888);
			l=identifierlist();
			state._fsp--;

			match(input, Token.UP, null); 


						if (offset.bitLength() > 64) {
							throw new SleighError("Unsupported offset: " + String.format("0x%x", offset),
								l.second.get(0));
						}
						if (size.bitLength() >= 32) {
							throw new SleighError("Unsupported size: " + String.format("0x%x", size),
								l.second.get(0));
						}
						sc.defineVarnodes(s, toULong(offset), toUInt(size), l.first, l.second);
					
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
	// ghidra/sleigh/grammar/SleighCompiler.g:504:1: identifierlist returns [Pair<VectorSTL<String>,VectorSTL<Location>> value] : ^( OP_IDENTIFIER_LIST ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )+ ) ;
	public final Pair<VectorSTL<String>,VectorSTL<Location>> identifierlist() throws RecognitionException {
		Pair<VectorSTL<String>,VectorSTL<Location>> value = null;


		CommonTree t=null;
		CommonTree s=null;


				VectorSTL<String> names = new VectorSTL<String>();
				VectorSTL<Location> locations = new VectorSTL<Location>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:512:2: ( ^( OP_IDENTIFIER_LIST ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )+ ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:512:4: ^( OP_IDENTIFIER_LIST ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )+ )
			{
			match(input,OP_IDENTIFIER_LIST,FOLLOW_OP_IDENTIFIER_LIST_in_identifierlist919); 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighCompiler.g:512:25: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )+
			int cnt19=0;
			loop19:
			while (true) {
				int alt19=3;
				int LA19_0 = input.LA(1);
				if ( (LA19_0==OP_IDENTIFIER) ) {
					alt19=1;
				}
				else if ( (LA19_0==OP_WILDCARD) ) {
					alt19=2;
				}

				switch (alt19) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:513:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_identifierlist927); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 names.push_back(s.getText()); locations.push_back(find(s)); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:514:6: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_identifierlist943); 
					 names.push_back(t.getText()); locations.push_back(find(t)); 
					}
					break;

				default :
					if ( cnt19 >= 1 ) break loop19;
					EarlyExitException eee = new EarlyExitException(19, input);
					throw eee;
				}
				cnt19++;
			}

			match(input, Token.UP, null); 

			}


					value = new Pair<VectorSTL<String>,VectorSTL<Location>>(names, locations);
				
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
	// ghidra/sleigh/grammar/SleighCompiler.g:517:1: stringoridentlist returns [VectorSTL<String> value] : ^( OP_STRING_OR_IDENT_LIST (n= stringorident )* ) ;
	public final VectorSTL<String> stringoridentlist() throws RecognitionException {
		VectorSTL<String> value = null;


		String n =null;


				value = new VectorSTL<String>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:521:2: ( ^( OP_STRING_OR_IDENT_LIST (n= stringorident )* ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:521:4: ^( OP_STRING_OR_IDENT_LIST (n= stringorident )* )
			{
			match(input,OP_STRING_OR_IDENT_LIST,FOLLOW_OP_STRING_OR_IDENT_LIST_in_stringoridentlist971); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				// ghidra/sleigh/grammar/SleighCompiler.g:521:30: (n= stringorident )*
				loop20:
				while (true) {
					int alt20=2;
					int LA20_0 = input.LA(1);
					if ( (LA20_0==OP_IDENTIFIER||LA20_0==OP_QSTRING||LA20_0==OP_WILDCARD) ) {
						alt20=1;
					}

					switch (alt20) {
					case 1 :
						// ghidra/sleigh/grammar/SleighCompiler.g:521:31: n= stringorident
						{
						pushFollow(FOLLOW_stringorident_in_stringoridentlist976);
						n=stringorident();
						state._fsp--;

						 value.push_back(n); 
						}
						break;

					default :
						break loop20;
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
	// $ANTLR end "stringoridentlist"



	// $ANTLR start "stringorident"
	// ghidra/sleigh/grammar/SleighCompiler.g:524:1: stringorident returns [String value] : (n= identifier |s= qstring );
	public final String stringorident() throws RecognitionException {
		String value = null;


		TreeRuleReturnScope n =null;
		String s =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:525:2: (n= identifier |s= qstring )
			int alt21=2;
			int LA21_0 = input.LA(1);
			if ( (LA21_0==OP_IDENTIFIER||LA21_0==OP_WILDCARD) ) {
				alt21=1;
			}
			else if ( (LA21_0==OP_QSTRING) ) {
				alt21=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 21, 0, input);
				throw nvae;
			}

			switch (alt21) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:525:4: n= identifier
					{
					pushFollow(FOLLOW_identifier_in_stringorident999);
					n=identifier();
					state._fsp--;

					 value = (n!=null?((SleighCompiler.identifier_return)n).value:null); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:526:4: s= qstring
					{
					pushFollow(FOLLOW_qstring_in_stringorident1008);
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
	// ghidra/sleigh/grammar/SleighCompiler.g:529:1: bitrangedef : ^( OP_BITRANGES ( sbitrange )+ ) ;
	public final void bitrangedef() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:530:2: ( ^( OP_BITRANGES ( sbitrange )+ ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:530:4: ^( OP_BITRANGES ( sbitrange )+ )
			{
			match(input,OP_BITRANGES,FOLLOW_OP_BITRANGES_in_bitrangedef1022); 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighCompiler.g:530:19: ( sbitrange )+
			int cnt22=0;
			loop22:
			while (true) {
				int alt22=2;
				int LA22_0 = input.LA(1);
				if ( (LA22_0==OP_BITRANGE) ) {
					alt22=1;
				}

				switch (alt22) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:530:19: sbitrange
					{
					pushFollow(FOLLOW_sbitrange_in_bitrangedef1024);
					sbitrange();
					state._fsp--;

					}
					break;

				default :
					if ( cnt22 >= 1 ) break loop22;
					EarlyExitException eee = new EarlyExitException(22, input);
					throw eee;
				}
				cnt22++;
			}

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



	// $ANTLR start "sbitrange"
	// ghidra/sleigh/grammar/SleighCompiler.g:533:1: sbitrange : ^( OP_BITRANGE ^( OP_IDENTIFIER s= . ) b= varnode_symbol[\"bitrange definition\", true] i= integer j= integer ) ;
	public final void sbitrange() throws RecognitionException {
		CommonTree s=null;
		VarnodeSymbol b =null;
		RadixBigInteger i =null;
		RadixBigInteger j =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:534:2: ( ^( OP_BITRANGE ^( OP_IDENTIFIER s= . ) b= varnode_symbol[\"bitrange definition\", true] i= integer j= integer ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:534:4: ^( OP_BITRANGE ^( OP_IDENTIFIER s= . ) b= varnode_symbol[\"bitrange definition\", true] i= integer j= integer )
			{
			match(input,OP_BITRANGE,FOLLOW_OP_BITRANGE_in_sbitrange1038); 
			match(input, Token.DOWN, null); 
			match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_sbitrange1041); 
			match(input, Token.DOWN, null); 
			s=(CommonTree)input.LT(1);
			matchAny(input); 
			match(input, Token.UP, null); 

			pushFollow(FOLLOW_varnode_symbol_in_sbitrange1050);
			b=varnode_symbol("bitrange definition", true);
			state._fsp--;

			pushFollow(FOLLOW_integer_in_sbitrange1055);
			i=integer();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_sbitrange1059);
			j=integer();
			state._fsp--;

			match(input, Token.UP, null); 


						sc.defineBitrange(find(s), s.getText(), b, toUInt(i), toUInt(j));
					
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
	// $ANTLR end "sbitrange"



	// $ANTLR start "pcodeopdef"
	// ghidra/sleigh/grammar/SleighCompiler.g:539:1: pcodeopdef : ^( OP_PCODEOP l= identifierlist ) ;
	public final void pcodeopdef() throws RecognitionException {
		Pair<VectorSTL<String>,VectorSTL<Location>> l =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:540:2: ( ^( OP_PCODEOP l= identifierlist ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:540:4: ^( OP_PCODEOP l= identifierlist )
			{
			match(input,OP_PCODEOP,FOLLOW_OP_PCODEOP_in_pcodeopdef1074); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifierlist_in_pcodeopdef1078);
			l=identifierlist();
			state._fsp--;

			match(input, Token.UP, null); 

			 sc.addUserOp(l.first, l.second); 
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
	// ghidra/sleigh/grammar/SleighCompiler.g:543:1: valueattach : ^( OP_VALUES a= valuelist[\"attach values\"] b= intblist ) ;
	public final void valueattach() throws RecognitionException {
		Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> a =null;
		VectorSTL<Long> b =null;


				sc.calcContextLayout();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:547:2: ( ^( OP_VALUES a= valuelist[\"attach values\"] b= intblist ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:547:4: ^( OP_VALUES a= valuelist[\"attach values\"] b= intblist )
			{
			match(input,OP_VALUES,FOLLOW_OP_VALUES_in_valueattach1099); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_valuelist_in_valueattach1103);
			a=valuelist("attach values");
			state._fsp--;

			pushFollow(FOLLOW_intblist_in_valueattach1108);
			b=intblist();
			state._fsp--;

			match(input, Token.UP, null); 

			 sc.attachValues(a.first, a.second, b); 
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
	// ghidra/sleigh/grammar/SleighCompiler.g:550:1: intblist returns [VectorSTL<Long> value] : ^( OP_INTBLIST (n= intbpart )* ) ;
	public final VectorSTL<Long> intblist() throws RecognitionException {
		VectorSTL<Long> value = null;


		RadixBigInteger n =null;


				value = new VectorSTL<Long>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:554:2: ( ^( OP_INTBLIST (n= intbpart )* ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:554:4: ^( OP_INTBLIST (n= intbpart )* )
			{
			match(input,OP_INTBLIST,FOLLOW_OP_INTBLIST_in_intblist1133); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				// ghidra/sleigh/grammar/SleighCompiler.g:554:18: (n= intbpart )*
				loop23:
				while (true) {
					int alt23=2;
					int LA23_0 = input.LA(1);
					if ( (LA23_0==OP_BIN_CONSTANT||LA23_0==OP_DEC_CONSTANT||LA23_0==OP_HEX_CONSTANT||LA23_0==OP_NEGATE||LA23_0==OP_WILDCARD) ) {
						alt23=1;
					}

					switch (alt23) {
					case 1 :
						// ghidra/sleigh/grammar/SleighCompiler.g:554:19: n= intbpart
						{
						pushFollow(FOLLOW_intbpart_in_intblist1138);
						n=intbpart();
						state._fsp--;

						 value.push_back(toLong(n)); 
						}
						break;

					default :
						break loop23;
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
	// $ANTLR end "intblist"



	// $ANTLR start "intbpart"
	// ghidra/sleigh/grammar/SleighCompiler.g:557:1: intbpart returns [RadixBigInteger value] : (t= OP_WILDCARD | ^( OP_NEGATE i= integer ) |i= integer );
	public final RadixBigInteger intbpart() throws RecognitionException {
		RadixBigInteger value = null;


		CommonTree t=null;
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:558:2: (t= OP_WILDCARD | ^( OP_NEGATE i= integer ) |i= integer )
			int alt24=3;
			switch ( input.LA(1) ) {
			case OP_WILDCARD:
				{
				alt24=1;
				}
				break;
			case OP_NEGATE:
				{
				alt24=2;
				}
				break;
			case OP_BIN_CONSTANT:
			case OP_DEC_CONSTANT:
			case OP_HEX_CONSTANT:
				{
				alt24=3;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 24, 0, input);
				throw nvae;
			}
			switch (alt24) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:558:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_intbpart1161); 
					 value = new RadixBigInteger(find(t), "BADBEEF", 16); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:559:4: ^( OP_NEGATE i= integer )
					{
					match(input,OP_NEGATE,FOLLOW_OP_NEGATE_in_intbpart1169); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_intbpart1173);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = i.negate(); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:560:4: i= integer
					{
					pushFollow(FOLLOW_integer_in_intbpart1183);
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
	// ghidra/sleigh/grammar/SleighCompiler.g:563:1: nameattach : ^( OP_NAMES a= valuelist[\"attach variables\"] b= stringoridentlist ) ;
	public final void nameattach() throws RecognitionException {
		Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> a =null;
		VectorSTL<String> b =null;


				sc.calcContextLayout();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:567:2: ( ^( OP_NAMES a= valuelist[\"attach variables\"] b= stringoridentlist ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:567:4: ^( OP_NAMES a= valuelist[\"attach variables\"] b= stringoridentlist )
			{
			match(input,OP_NAMES,FOLLOW_OP_NAMES_in_nameattach1203); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_valuelist_in_nameattach1207);
			a=valuelist("attach variables");
			state._fsp--;

			pushFollow(FOLLOW_stringoridentlist_in_nameattach1212);
			b=stringoridentlist();
			state._fsp--;

			match(input, Token.UP, null); 

			 sc.attachNames(a.first, a.second, b); 
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
	// ghidra/sleigh/grammar/SleighCompiler.g:570:1: varattach : ^( OP_VARIABLES a= valuelist[\"attach variables\"] b= varlist[\"attach variables\"] ) ;
	public final void varattach() throws RecognitionException {
		Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> a =null;
		VectorSTL<SleighSymbol> b =null;


				sc.calcContextLayout();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:574:2: ( ^( OP_VARIABLES a= valuelist[\"attach variables\"] b= varlist[\"attach variables\"] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:574:4: ^( OP_VARIABLES a= valuelist[\"attach variables\"] b= varlist[\"attach variables\"] )
			{
			match(input,OP_VARIABLES,FOLLOW_OP_VARIABLES_in_varattach1233); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_valuelist_in_varattach1237);
			a=valuelist("attach variables");
			state._fsp--;

			pushFollow(FOLLOW_varlist_in_varattach1242);
			b=varlist("attach variables");
			state._fsp--;

			match(input, Token.UP, null); 


						sc.attachVarnodes(a.first, a.second, b);
					
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



	// $ANTLR start "valuelist"
	// ghidra/sleigh/grammar/SleighCompiler.g:579:1: valuelist[String purpose] returns [Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> value] : ^( OP_IDENTIFIER_LIST (n= value_symbol[purpose] )+ ) ;
	public final Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> valuelist(String purpose) throws RecognitionException {
		Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> value = null;


		Pair<ValueSymbol,Location> n =null;


				VectorSTL<SleighSymbol> symbols = new VectorSTL<SleighSymbol>();
				VectorSTL<Location> locations = new VectorSTL<Location>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:587:2: ( ^( OP_IDENTIFIER_LIST (n= value_symbol[purpose] )+ ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:587:4: ^( OP_IDENTIFIER_LIST (n= value_symbol[purpose] )+ )
			{
			match(input,OP_IDENTIFIER_LIST,FOLLOW_OP_IDENTIFIER_LIST_in_valuelist1275); 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighCompiler.g:587:25: (n= value_symbol[purpose] )+
			int cnt25=0;
			loop25:
			while (true) {
				int alt25=2;
				int LA25_0 = input.LA(1);
				if ( (LA25_0==OP_IDENTIFIER||LA25_0==OP_WILDCARD) ) {
					alt25=1;
				}

				switch (alt25) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:587:26: n= value_symbol[purpose]
					{
					pushFollow(FOLLOW_value_symbol_in_valuelist1280);
					n=value_symbol(purpose);
					state._fsp--;


								symbols.push_back(n.first);
								locations.push_back(n.second);
							
					}
					break;

				default :
					if ( cnt25 >= 1 ) break loop25;
					EarlyExitException eee = new EarlyExitException(25, input);
					throw eee;
				}
				cnt25++;
			}

			match(input, Token.UP, null); 

			}


					value = new Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>>(symbols, locations);
				
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
	// $ANTLR end "valuelist"



	// $ANTLR start "varlist"
	// ghidra/sleigh/grammar/SleighCompiler.g:594:1: varlist[String purpose] returns [VectorSTL<SleighSymbol> value] : ^( OP_IDENTIFIER_LIST (n= varnode_symbol[purpose, false] )+ ) ;
	public final VectorSTL<SleighSymbol> varlist(String purpose) throws RecognitionException {
		VectorSTL<SleighSymbol> value = null;


		VarnodeSymbol n =null;


				value = new VectorSTL<SleighSymbol>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:598:2: ( ^( OP_IDENTIFIER_LIST (n= varnode_symbol[purpose, false] )+ ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:598:4: ^( OP_IDENTIFIER_LIST (n= varnode_symbol[purpose, false] )+ )
			{
			match(input,OP_IDENTIFIER_LIST,FOLLOW_OP_IDENTIFIER_LIST_in_varlist1311); 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighCompiler.g:598:25: (n= varnode_symbol[purpose, false] )+
			int cnt26=0;
			loop26:
			while (true) {
				int alt26=2;
				int LA26_0 = input.LA(1);
				if ( (LA26_0==OP_IDENTIFIER||LA26_0==OP_WILDCARD) ) {
					alt26=1;
				}

				switch (alt26) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:598:26: n= varnode_symbol[purpose, false]
					{
					pushFollow(FOLLOW_varnode_symbol_in_varlist1316);
					n=varnode_symbol(purpose, false);
					state._fsp--;


								value.push_back(n);
							
					}
					break;

				default :
					if ( cnt26 >= 1 ) break loop26;
					EarlyExitException eee = new EarlyExitException(26, input);
					throw eee;
				}
				cnt26++;
			}

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
		return value;
	}
	// $ANTLR end "varlist"



	// $ANTLR start "constructorlike"
	// ghidra/sleigh/grammar/SleighCompiler.g:603:1: constructorlike : ( macrodef | withblock | constructor );
	public final void constructorlike() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:604:2: ( macrodef | withblock | constructor )
			int alt27=3;
			switch ( input.LA(1) ) {
			case OP_MACRO:
				{
				alt27=1;
				}
				break;
			case OP_WITH:
				{
				alt27=2;
				}
				break;
			case OP_CONSTRUCTOR:
				{
				alt27=3;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 27, 0, input);
				throw nvae;
			}
			switch (alt27) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:604:4: macrodef
					{
					pushFollow(FOLLOW_macrodef_in_constructorlike1334);
					macrodef();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:605:4: withblock
					{
					 sc.calcContextLayout(); 
					pushFollow(FOLLOW_withblock_in_constructorlike1341);
					withblock();
					state._fsp--;

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:606:4: constructor
					{
					 sc.calcContextLayout(); 
					pushFollow(FOLLOW_constructor_in_constructorlike1348);
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


	protected static class macrodef_scope {
		ConstructTpl macrobody;
	}
	protected Stack<macrodef_scope> macrodef_stack = new Stack<macrodef_scope>();


	// $ANTLR start "macrodef"
	// ghidra/sleigh/grammar/SleighCompiler.g:609:1: macrodef : ^(t= OP_MACRO n= unbound_identifier[\"macro\"] a= arguments s= semantic[env, null, sc.pcode, $t, false, true] ) ;
	public final void macrodef() throws RecognitionException {
		macrodef_stack.push(new macrodef_scope());
		CommonTree t=null;
		Tree n =null;
		Pair<VectorSTL<String>,VectorSTL<Location>> a =null;
		SectionVector s =null;


				MacroSymbol symbol = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:616:2: ( ^(t= OP_MACRO n= unbound_identifier[\"macro\"] a= arguments s= semantic[env, null, sc.pcode, $t, false, true] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:616:4: ^(t= OP_MACRO n= unbound_identifier[\"macro\"] a= arguments s= semantic[env, null, sc.pcode, $t, false, true] )
			{
			t=(CommonTree)match(input,OP_MACRO,FOLLOW_OP_MACRO_in_macrodef1373); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_unbound_identifier_in_macrodef1377);
			n=unbound_identifier("macro");
			state._fsp--;

			pushFollow(FOLLOW_arguments_in_macrodef1382);
			a=arguments();
			state._fsp--;


						symbol = sc.createMacro(find(n), n.getText(), a.first, a.second);
					
			pushFollow(FOLLOW_semantic_in_macrodef1388);
			s=semantic(env, null, sc.pcode, t, false, true);
			state._fsp--;

			match(input, Token.UP, null); 


						if (symbol != null) {
							sc.buildMacro(symbol, macrodef_stack.peek().macrobody);
						}
					
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			macrodef_stack.pop();
		}
	}
	// $ANTLR end "macrodef"



	// $ANTLR start "arguments"
	// ghidra/sleigh/grammar/SleighCompiler.g:625:1: arguments returns [Pair<VectorSTL<String>,VectorSTL<Location>> value] : ( ^( OP_ARGUMENTS ( ^( OP_IDENTIFIER s= . ) )+ ) | OP_EMPTY_LIST );
	public final Pair<VectorSTL<String>,VectorSTL<Location>> arguments() throws RecognitionException {
		Pair<VectorSTL<String>,VectorSTL<Location>> value = null;


		CommonTree s=null;


				VectorSTL<String> names = new VectorSTL<String>();
				VectorSTL<Location> locations = new VectorSTL<Location>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:633:2: ( ^( OP_ARGUMENTS ( ^( OP_IDENTIFIER s= . ) )+ ) | OP_EMPTY_LIST )
			int alt29=2;
			int LA29_0 = input.LA(1);
			if ( (LA29_0==OP_ARGUMENTS) ) {
				alt29=1;
			}
			else if ( (LA29_0==OP_EMPTY_LIST) ) {
				alt29=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 29, 0, input);
				throw nvae;
			}

			switch (alt29) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:633:4: ^( OP_ARGUMENTS ( ^( OP_IDENTIFIER s= . ) )+ )
					{
					match(input,OP_ARGUMENTS,FOLLOW_OP_ARGUMENTS_in_arguments1420); 
					match(input, Token.DOWN, null); 
					// ghidra/sleigh/grammar/SleighCompiler.g:633:19: ( ^( OP_IDENTIFIER s= . ) )+
					int cnt28=0;
					loop28:
					while (true) {
						int alt28=2;
						int LA28_0 = input.LA(1);
						if ( (LA28_0==OP_IDENTIFIER) ) {
							alt28=1;
						}

						switch (alt28) {
						case 1 :
							// ghidra/sleigh/grammar/SleighCompiler.g:633:20: ^( OP_IDENTIFIER s= . )
							{
							match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_arguments1424); 
							match(input, Token.DOWN, null); 
							s=(CommonTree)input.LT(1);
							matchAny(input); 
							match(input, Token.UP, null); 

							 names.push_back(s.getText()); locations.push_back(find(s)); 
							}
							break;

						default :
							if ( cnt28 >= 1 ) break loop28;
							EarlyExitException eee = new EarlyExitException(28, input);
							throw eee;
						}
						cnt28++;
					}

					match(input, Token.UP, null); 

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:634:4: OP_EMPTY_LIST
					{
					match(input,OP_EMPTY_LIST,FOLLOW_OP_EMPTY_LIST_in_arguments1439); 
					}
					break;

			}

					value = new Pair<VectorSTL<String>,VectorSTL<Location>>(names, locations);
				
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



	// $ANTLR start "withblock"
	// ghidra/sleigh/grammar/SleighCompiler.g:637:1: withblock : ^( OP_WITH s= id_or_nil e= bitpat_or_nil b= contextblock constructorlikelist ) ;
	public final void withblock() throws RecognitionException {
		TreeRuleReturnScope s =null;
		PatternEquation e =null;
		VectorSTL<ContextChange> b =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:638:2: ( ^( OP_WITH s= id_or_nil e= bitpat_or_nil b= contextblock constructorlikelist ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:638:4: ^( OP_WITH s= id_or_nil e= bitpat_or_nil b= contextblock constructorlikelist )
			{
			match(input,OP_WITH,FOLLOW_OP_WITH_in_withblock1451); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_id_or_nil_in_withblock1455);
			s=id_or_nil();
			state._fsp--;

			pushFollow(FOLLOW_bitpat_or_nil_in_withblock1459);
			e=bitpat_or_nil();
			state._fsp--;

			pushFollow(FOLLOW_contextblock_in_withblock1463);
			b=contextblock();
			state._fsp--;


						SubtableSymbol ss = null;
						if ((s!=null?((SleighCompiler.id_or_nil_return)s).value:null) != null) {
							ss = findOrNewTable(find((s!=null?((SleighCompiler.id_or_nil_return)s).tree:null)), (s!=null?((SleighCompiler.id_or_nil_return)s).value:null));
							if (ss == null) bail("With block with invalid subtable identifier");
						}	
						sc.pushWith(ss, e, b);
					
			pushFollow(FOLLOW_constructorlikelist_in_withblock1469);
			constructorlikelist();
			state._fsp--;


						sc.popWith();
					
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
	// $ANTLR end "withblock"


	public static class id_or_nil_return extends TreeRuleReturnScope {
		public String value;
		public Tree tree;
	};


	// $ANTLR start "id_or_nil"
	// ghidra/sleigh/grammar/SleighCompiler.g:652:1: id_or_nil returns [String value, Tree tree] : (v= identifier | OP_NIL );
	public final SleighCompiler.id_or_nil_return id_or_nil() throws RecognitionException {
		SleighCompiler.id_or_nil_return retval = new SleighCompiler.id_or_nil_return();
		retval.start = input.LT(1);

		TreeRuleReturnScope v =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:653:2: (v= identifier | OP_NIL )
			int alt30=2;
			int LA30_0 = input.LA(1);
			if ( (LA30_0==OP_IDENTIFIER||LA30_0==OP_WILDCARD) ) {
				alt30=1;
			}
			else if ( (LA30_0==OP_NIL) ) {
				alt30=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 30, 0, input);
				throw nvae;
			}

			switch (alt30) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:653:4: v= identifier
					{
					pushFollow(FOLLOW_identifier_in_id_or_nil1491);
					v=identifier();
					state._fsp--;

					 retval.value = (v!=null?((SleighCompiler.identifier_return)v).value:null); retval.tree = (v!=null?((SleighCompiler.identifier_return)v).tree:null); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:654:4: OP_NIL
					{
					match(input,OP_NIL,FOLLOW_OP_NIL_in_id_or_nil1498); 
					 retval.value = null; retval.tree = null; 
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
		return retval;
	}
	// $ANTLR end "id_or_nil"



	// $ANTLR start "bitpat_or_nil"
	// ghidra/sleigh/grammar/SleighCompiler.g:657:1: bitpat_or_nil returns [PatternEquation value] : (v= bitpattern | OP_NIL );
	public final PatternEquation bitpat_or_nil() throws RecognitionException {
		PatternEquation value = null;


		PatternEquation v =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:658:2: (v= bitpattern | OP_NIL )
			int alt31=2;
			int LA31_0 = input.LA(1);
			if ( (LA31_0==OP_BIT_PATTERN) ) {
				alt31=1;
			}
			else if ( (LA31_0==OP_NIL) ) {
				alt31=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 31, 0, input);
				throw nvae;
			}

			switch (alt31) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:658:4: v= bitpattern
					{
					pushFollow(FOLLOW_bitpattern_in_bitpat_or_nil1517);
					v=bitpattern();
					state._fsp--;

					 value = v; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:659:4: OP_NIL
					{
					match(input,OP_NIL,FOLLOW_OP_NIL_in_bitpat_or_nil1524); 
					 value = null; 
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
	// $ANTLR end "bitpat_or_nil"



	// $ANTLR start "constructorlikelist"
	// ghidra/sleigh/grammar/SleighCompiler.g:662:1: constructorlikelist : ^( OP_CTLIST ( definition | constructorlike )* ) ;
	public final void constructorlikelist() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:663:2: ( ^( OP_CTLIST ( definition | constructorlike )* ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:663:4: ^( OP_CTLIST ( definition | constructorlike )* )
			{
			match(input,OP_CTLIST,FOLLOW_OP_CTLIST_in_constructorlikelist1538); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				// ghidra/sleigh/grammar/SleighCompiler.g:663:16: ( definition | constructorlike )*
				loop32:
				while (true) {
					int alt32=3;
					int LA32_0 = input.LA(1);
					if ( (LA32_0==OP_ALIGNMENT||LA32_0==OP_BITRANGES||LA32_0==OP_CONTEXT||LA32_0==OP_NAMES||LA32_0==OP_PCODEOP||LA32_0==OP_SPACE||(LA32_0 >= OP_TOKEN && LA32_0 <= OP_TOKEN_ENDIAN)||(LA32_0 >= OP_VALUES && LA32_0 <= OP_VARNODE)) ) {
						alt32=1;
					}
					else if ( (LA32_0==OP_CONSTRUCTOR||LA32_0==OP_MACRO||LA32_0==OP_WITH) ) {
						alt32=2;
					}

					switch (alt32) {
					case 1 :
						// ghidra/sleigh/grammar/SleighCompiler.g:663:18: definition
						{
						pushFollow(FOLLOW_definition_in_constructorlikelist1542);
						definition();
						state._fsp--;

						}
						break;
					case 2 :
						// ghidra/sleigh/grammar/SleighCompiler.g:663:31: constructorlike
						{
						pushFollow(FOLLOW_constructorlike_in_constructorlikelist1546);
						constructorlike();
						state._fsp--;

						}
						break;

					default :
						break loop32;
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
	}
	// $ANTLR end "constructorlikelist"



	// $ANTLR start "constructor"
	// ghidra/sleigh/grammar/SleighCompiler.g:666:1: constructor : ^( OP_CONSTRUCTOR c= ctorstart e= bitpattern b= contextblock r= ctorsemantic[c] ) ;
	public final void constructor() throws RecognitionException {
		Constructor c =null;
		PatternEquation e =null;
		VectorSTL<ContextChange> b =null;
		SectionVector r =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:667:2: ( ^( OP_CONSTRUCTOR c= ctorstart e= bitpattern b= contextblock r= ctorsemantic[c] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:667:4: ^( OP_CONSTRUCTOR c= ctorstart e= bitpattern b= contextblock r= ctorsemantic[c] )
			{
			match(input,OP_CONSTRUCTOR,FOLLOW_OP_CONSTRUCTOR_in_constructor1563); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_ctorstart_in_constructor1567);
			c=ctorstart();
			state._fsp--;

			pushFollow(FOLLOW_bitpattern_in_constructor1571);
			e=bitpattern();
			state._fsp--;

			pushFollow(FOLLOW_contextblock_in_constructor1575);
			b=contextblock();
			state._fsp--;

			pushFollow(FOLLOW_ctorsemantic_in_constructor1579);
			r=ctorsemantic(c);
			state._fsp--;

			match(input, Token.UP, null); 


						sc.buildConstructor(c, e, b, r);
					
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
	// ghidra/sleigh/grammar/SleighCompiler.g:672:1: ctorsemantic[Constructor ctor] returns [SectionVector value] : ( ^(t= OP_PCODE p= semantic[env, ctor.location, sc.pcode, $t, true, false] ) | ^( OP_PCODE OP_UNIMPL ) );
	public final SectionVector ctorsemantic(Constructor ctor) throws RecognitionException {
		SectionVector value = null;


		CommonTree t=null;
		SectionVector p =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:673:2: ( ^(t= OP_PCODE p= semantic[env, ctor.location, sc.pcode, $t, true, false] ) | ^( OP_PCODE OP_UNIMPL ) )
			int alt33=2;
			int LA33_0 = input.LA(1);
			if ( (LA33_0==OP_PCODE) ) {
				int LA33_1 = input.LA(2);
				if ( (LA33_1==DOWN) ) {
					int LA33_2 = input.LA(3);
					if ( (LA33_2==OP_UNIMPL) ) {
						alt33=2;
					}
					else if ( (LA33_2==OP_SEMANTIC) ) {
						alt33=1;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 33, 2, input);
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
							new NoViableAltException("", 33, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 33, 0, input);
				throw nvae;
			}

			switch (alt33) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:673:4: ^(t= OP_PCODE p= semantic[env, ctor.location, sc.pcode, $t, true, false] )
					{
					t=(CommonTree)match(input,OP_PCODE,FOLLOW_OP_PCODE_in_ctorsemantic1602); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_semantic_in_ctorsemantic1606);
					p=semantic(env, ctor.location, sc.pcode, t, true, false);
					state._fsp--;

					match(input, Token.UP, null); 

					       value = p; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:674:4: ^( OP_PCODE OP_UNIMPL )
					{
					match(input,OP_PCODE,FOLLOW_OP_PCODE_in_ctorsemantic1616); 
					match(input, Token.DOWN, null); 
					match(input,OP_UNIMPL,FOLLOW_OP_UNIMPL_in_ctorsemantic1618); 
					match(input, Token.UP, null); 

					 /*unimpl unimplemented ; */ value = null; 
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
	// $ANTLR end "ctorsemantic"



	// $ANTLR start "bitpattern"
	// ghidra/sleigh/grammar/SleighCompiler.g:677:1: bitpattern returns [PatternEquation value] : ^( OP_BIT_PATTERN p= pequation ) ;
	public final PatternEquation bitpattern() throws RecognitionException {
		PatternEquation value = null;


		PatternEquation p =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:678:2: ( ^( OP_BIT_PATTERN p= pequation ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:678:4: ^( OP_BIT_PATTERN p= pequation )
			{
			match(input,OP_BIT_PATTERN,FOLLOW_OP_BIT_PATTERN_in_bitpattern1637); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_pequation_in_bitpattern1641);
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


	protected static class ctorstart_scope {
		boolean table;
		boolean firstTime;
	}
	protected Stack<ctorstart_scope> ctorstart_stack = new Stack<ctorstart_scope>();


	// $ANTLR start "ctorstart"
	// ghidra/sleigh/grammar/SleighCompiler.g:681:1: ctorstart returns [Constructor value] : ( ^(t= OP_SUBTABLE ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) d= display[value] ) | ^(t= OP_TABLE d= display[value] ) );
	public final Constructor ctorstart() throws RecognitionException {
		ctorstart_stack.push(new ctorstart_scope());
		Constructor value = null;


		CommonTree t=null;
		CommonTree s=null;


				ctorstart_stack.peek().table = false;
				ctorstart_stack.peek().firstTime = true;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:690:2: ( ^(t= OP_SUBTABLE ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) d= display[value] ) | ^(t= OP_TABLE d= display[value] ) )
			int alt35=2;
			int LA35_0 = input.LA(1);
			if ( (LA35_0==OP_SUBTABLE) ) {
				alt35=1;
			}
			else if ( (LA35_0==OP_TABLE) ) {
				alt35=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 35, 0, input);
				throw nvae;
			}

			switch (alt35) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:690:4: ^(t= OP_SUBTABLE ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) d= display[value] )
					{
					t=(CommonTree)match(input,OP_SUBTABLE,FOLLOW_OP_SUBTABLE_in_ctorstart1673); 
					match(input, Token.DOWN, null); 
					// ghidra/sleigh/grammar/SleighCompiler.g:690:20: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
					int alt34=2;
					int LA34_0 = input.LA(1);
					if ( (LA34_0==OP_IDENTIFIER) ) {
						alt34=1;
					}
					else if ( (LA34_0==OP_WILDCARD) ) {
						alt34=2;
					}

					else {
						NoViableAltException nvae =
							new NoViableAltException("", 34, 0, input);
						throw nvae;
					}

					switch (alt34) {
						case 1 :
							// ghidra/sleigh/grammar/SleighCompiler.g:690:21: ^( OP_IDENTIFIER s= . )
							{
							match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_ctorstart1677); 
							match(input, Token.DOWN, null); 
							s=(CommonTree)input.LT(1);
							matchAny(input); 
							match(input, Token.UP, null); 


										SubtableSymbol ss = findOrNewTable(find(s), s.getText());
										if (ss != null) {
											value = sc.createConstructor(find(t), ss);
										}
									
							}
							break;
						case 2 :
							// ghidra/sleigh/grammar/SleighCompiler.g:696:4: t= OP_WILDCARD
							{
							t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_ctorstart1691); 

										wildcardError(t, "subconstructor");
									
							}
							break;

					}

					pushFollow(FOLLOW_display_in_ctorstart1698);
					display(value);
					state._fsp--;

					match(input, Token.UP, null); 

					  
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:699:4: ^(t= OP_TABLE d= display[value] )
					{
					t=(CommonTree)match(input,OP_TABLE,FOLLOW_OP_TABLE_in_ctorstart1710); 

								value = sc.createConstructor(find(t), null);
								ctorstart_stack.peek().table = "instruction".equals(value.getParent().getName());
							
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_display_in_ctorstart1716);
					display(value);
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
			ctorstart_stack.pop();
		}
		return value;
	}
	// $ANTLR end "ctorstart"



	// $ANTLR start "display"
	// ghidra/sleigh/grammar/SleighCompiler.g:705:1: display[Constructor ct] : ^( OP_DISPLAY p= pieces[ct] ) ;
	public final void display(Constructor ct) throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:706:2: ( ^( OP_DISPLAY p= pieces[ct] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:706:4: ^( OP_DISPLAY p= pieces[ct] )
			{
			match(input,OP_DISPLAY,FOLLOW_OP_DISPLAY_in_display1733); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				pushFollow(FOLLOW_pieces_in_display1737);
				pieces(ct);
				state._fsp--;

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
	// $ANTLR end "display"



	// $ANTLR start "pieces"
	// ghidra/sleigh/grammar/SleighCompiler.g:709:1: pieces[Constructor ct] : ( printpiece[ct] )* ;
	public final void pieces(Constructor ct) throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:710:2: ( ( printpiece[ct] )* )
			// ghidra/sleigh/grammar/SleighCompiler.g:710:4: ( printpiece[ct] )*
			{
			// ghidra/sleigh/grammar/SleighCompiler.g:710:4: ( printpiece[ct] )*
			loop36:
			while (true) {
				int alt36=2;
				int LA36_0 = input.LA(1);
				if ( (LA36_0==OP_CONCATENATE||LA36_0==OP_IDENTIFIER||LA36_0==OP_QSTRING||LA36_0==OP_STRING||LA36_0==OP_WHITESPACE) ) {
					alt36=1;
				}

				switch (alt36) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:710:4: printpiece[ct]
					{
					pushFollow(FOLLOW_printpiece_in_pieces1751);
					printpiece(ct);
					state._fsp--;

					}
					break;

				default :
					break loop36;
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
	// $ANTLR end "pieces"



	// $ANTLR start "printpiece"
	// ghidra/sleigh/grammar/SleighCompiler.g:713:1: printpiece[Constructor ct] : ( ^( OP_IDENTIFIER t= . ) |w= whitespace | OP_CONCATENATE |s= string );
	public final void printpiece(Constructor ct) throws RecognitionException {
		CommonTree t=null;
		String w =null;
		String s =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:717:2: ( ^( OP_IDENTIFIER t= . ) |w= whitespace | OP_CONCATENATE |s= string )
			int alt37=4;
			switch ( input.LA(1) ) {
			case OP_IDENTIFIER:
				{
				alt37=1;
				}
				break;
			case OP_WHITESPACE:
				{
				alt37=2;
				}
				break;
			case OP_CONCATENATE:
				{
				alt37=3;
				}
				break;
			case OP_QSTRING:
			case OP_STRING:
				{
				alt37=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 37, 0, input);
				throw nvae;
			}
			switch (alt37) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:717:4: ^( OP_IDENTIFIER t= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_printpiece1772); 
					match(input, Token.DOWN, null); 
					t=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								if (ctorstart_stack.peek().table && ctorstart_stack.peek().firstTime) {
									ct.addSyntax(t.getText());
								} else {
									sc.newOperand(find(t), ct, t.getText());
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:724:4: w= whitespace
					{
					pushFollow(FOLLOW_whitespace_in_printpiece1786);
					w=whitespace();
					state._fsp--;


								if (!ctorstart_stack.peek().firstTime) {
									ct.addSyntax(" ");
								}
							
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:729:4: OP_CONCATENATE
					{
					match(input,OP_CONCATENATE,FOLLOW_OP_CONCATENATE_in_printpiece1793); 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:730:4: s= string
					{
					pushFollow(FOLLOW_string_in_printpiece1800);
					s=string();
					state._fsp--;

					 ct.addSyntax(s); 
					}
					break;

			}

					ctorstart_stack.peek().firstTime = false;
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "printpiece"



	// $ANTLR start "whitespace"
	// ghidra/sleigh/grammar/SleighCompiler.g:733:1: whitespace returns [String value] : ^( OP_WHITESPACE s= . ) ;
	public final String whitespace() throws RecognitionException {
		String value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:734:2: ( ^( OP_WHITESPACE s= . ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:734:4: ^( OP_WHITESPACE s= . )
			{
			match(input,OP_WHITESPACE,FOLLOW_OP_WHITESPACE_in_whitespace1818); 
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
	// ghidra/sleigh/grammar/SleighCompiler.g:737:1: string returns [String value] : ( ^( OP_STRING s= . ) | ^( OP_QSTRING s= . ) );
	public final String string() throws RecognitionException {
		String value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:738:2: ( ^( OP_STRING s= . ) | ^( OP_QSTRING s= . ) )
			int alt38=2;
			int LA38_0 = input.LA(1);
			if ( (LA38_0==OP_STRING) ) {
				alt38=1;
			}
			else if ( (LA38_0==OP_QSTRING) ) {
				alt38=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 38, 0, input);
				throw nvae;
			}

			switch (alt38) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:738:4: ^( OP_STRING s= . )
					{
					match(input,OP_STRING,FOLLOW_OP_STRING_in_string1841); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = s.getText(); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:739:4: ^( OP_QSTRING s= . )
					{
					match(input,OP_QSTRING,FOLLOW_OP_QSTRING_in_string1854); 
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
	// $ANTLR end "string"



	// $ANTLR start "pequation"
	// ghidra/sleigh/grammar/SleighCompiler.g:742:1: pequation returns [PatternEquation value] : ( ^(t= OP_BOOL_OR l= pequation r= pequation ) | ^(t= OP_SEQUENCE l= pequation r= pequation ) | ^(t= OP_BOOL_AND l= pequation r= pequation ) | ^(t= OP_ELLIPSIS l= pequation ) | ^(t= OP_ELLIPSIS_RIGHT l= pequation ) | ^(t= OP_EQUAL s= family_or_operand_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_NOTEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_LESS f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_LESSEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_GREAT f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_GREATEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 ) |ps= pequation_symbol[\"pattern equation\"] | ^( OP_PARENTHESIZED l= pequation ) );
	public final PatternEquation pequation() throws RecognitionException {
		PatternEquation value = null;


		CommonTree t=null;
		PatternEquation l =null;
		PatternEquation r =null;
		Tree s =null;
		PatternExpression e =null;
		FamilySymbol f =null;
		PatternEquation ps =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:748:2: ( ^(t= OP_BOOL_OR l= pequation r= pequation ) | ^(t= OP_SEQUENCE l= pequation r= pequation ) | ^(t= OP_BOOL_AND l= pequation r= pequation ) | ^(t= OP_ELLIPSIS l= pequation ) | ^(t= OP_ELLIPSIS_RIGHT l= pequation ) | ^(t= OP_EQUAL s= family_or_operand_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_NOTEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_LESS f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_LESSEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_GREAT f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_GREATEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 ) |ps= pequation_symbol[\"pattern equation\"] | ^( OP_PARENTHESIZED l= pequation ) )
			int alt39=13;
			switch ( input.LA(1) ) {
			case OP_BOOL_OR:
				{
				alt39=1;
				}
				break;
			case OP_SEQUENCE:
				{
				alt39=2;
				}
				break;
			case OP_BOOL_AND:
				{
				alt39=3;
				}
				break;
			case OP_ELLIPSIS:
				{
				alt39=4;
				}
				break;
			case OP_ELLIPSIS_RIGHT:
				{
				alt39=5;
				}
				break;
			case OP_EQUAL:
				{
				alt39=6;
				}
				break;
			case OP_NOTEQUAL:
				{
				alt39=7;
				}
				break;
			case OP_LESS:
				{
				alt39=8;
				}
				break;
			case OP_LESSEQUAL:
				{
				alt39=9;
				}
				break;
			case OP_GREAT:
				{
				alt39=10;
				}
				break;
			case OP_GREATEQUAL:
				{
				alt39=11;
				}
				break;
			case OP_IDENTIFIER:
			case OP_WILDCARD:
				{
				alt39=12;
				}
				break;
			case OP_PARENTHESIZED:
				{
				alt39=13;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 39, 0, input);
				throw nvae;
			}
			switch (alt39) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:748:4: ^(t= OP_BOOL_OR l= pequation r= pequation )
					{
					t=(CommonTree)match(input,OP_BOOL_OR,FOLLOW_OP_BOOL_OR_in_pequation1885); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1889);
					l=pequation();
					state._fsp--;

					pushFollow(FOLLOW_pequation_in_pequation1893);
					r=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new EquationOr(find(t), l, r); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:749:4: ^(t= OP_SEQUENCE l= pequation r= pequation )
					{
					t=(CommonTree)match(input,OP_SEQUENCE,FOLLOW_OP_SEQUENCE_in_pequation1904); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1908);
					l=pequation();
					state._fsp--;

					pushFollow(FOLLOW_pequation_in_pequation1912);
					r=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new EquationCat(find(t), l, r); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:750:4: ^(t= OP_BOOL_AND l= pequation r= pequation )
					{
					t=(CommonTree)match(input,OP_BOOL_AND,FOLLOW_OP_BOOL_AND_in_pequation1923); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1927);
					l=pequation();
					state._fsp--;

					pushFollow(FOLLOW_pequation_in_pequation1931);
					r=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new EquationAnd(find(t), l, r); 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:752:4: ^(t= OP_ELLIPSIS l= pequation )
					{
					t=(CommonTree)match(input,OP_ELLIPSIS,FOLLOW_OP_ELLIPSIS_in_pequation1943); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1947);
					l=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new EquationLeftEllipsis(find(t), l); 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:753:4: ^(t= OP_ELLIPSIS_RIGHT l= pequation )
					{
					t=(CommonTree)match(input,OP_ELLIPSIS_RIGHT,FOLLOW_OP_ELLIPSIS_RIGHT_in_pequation1958); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1962);
					l=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new EquationRightEllipsis(find(t), l); 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:755:4: ^(t= OP_EQUAL s= family_or_operand_symbol[\"pattern equation\"] e= pexpression2 )
					{
					t=(CommonTree)match(input,OP_EQUAL,FOLLOW_OP_EQUAL_in_pequation1974); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_family_or_operand_symbol_in_pequation1978);
					s=family_or_operand_symbol("pattern equation");
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation1983);
					e=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym instanceof OperandSymbol) {
									value = sc.constrainOperand(find(t), (OperandSymbol) sym, e);
								} else {
									FamilySymbol fs = (FamilySymbol) sym;
									value = new EqualEquation(find(t), fs.getPatternValue(), e);
								}
							
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:764:4: ^(t= OP_NOTEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 )
					{
					t=(CommonTree)match(input,OP_NOTEQUAL,FOLLOW_OP_NOTEQUAL_in_pequation1994); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_family_symbol_in_pequation1998);
					f=family_symbol("pattern equation");
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation2003);
					e=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new NotEqualEquation(find(t), f.getPatternValue(), e); 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighCompiler.g:765:4: ^(t= OP_LESS f= family_symbol[\"pattern equation\"] e= pexpression2 )
					{
					t=(CommonTree)match(input,OP_LESS,FOLLOW_OP_LESS_in_pequation2014); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_family_symbol_in_pequation2018);
					f=family_symbol("pattern equation");
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation2023);
					e=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new LessEquation(find(t), f.getPatternValue(), e); 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighCompiler.g:766:4: ^(t= OP_LESSEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 )
					{
					t=(CommonTree)match(input,OP_LESSEQUAL,FOLLOW_OP_LESSEQUAL_in_pequation2034); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_family_symbol_in_pequation2038);
					f=family_symbol("pattern equation");
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation2043);
					e=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new LessEqualEquation(find(t), f.getPatternValue(), e); 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighCompiler.g:767:4: ^(t= OP_GREAT f= family_symbol[\"pattern equation\"] e= pexpression2 )
					{
					t=(CommonTree)match(input,OP_GREAT,FOLLOW_OP_GREAT_in_pequation2054); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_family_symbol_in_pequation2058);
					f=family_symbol("pattern equation");
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation2063);
					e=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new GreaterEquation(find(t), f.getPatternValue(), e); 
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighCompiler.g:768:4: ^(t= OP_GREATEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 )
					{
					t=(CommonTree)match(input,OP_GREATEQUAL,FOLLOW_OP_GREATEQUAL_in_pequation2074); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_family_symbol_in_pequation2078);
					f=family_symbol("pattern equation");
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation2083);
					e=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new GreaterEqualEquation(find(t), f.getPatternValue(), e); 
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighCompiler.g:770:4: ps= pequation_symbol[\"pattern equation\"]
					{
					pushFollow(FOLLOW_pequation_symbol_in_pequation2094);
					ps=pequation_symbol("pattern equation");
					state._fsp--;

					 value = ps; 
					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighCompiler.g:771:4: ^( OP_PARENTHESIZED l= pequation )
					{
					match(input,OP_PARENTHESIZED,FOLLOW_OP_PARENTHESIZED_in_pequation2103); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation2107);
					l=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l; 
					}
					break;

			}

					if (value == null) {
						throw new BailoutException("Pattern equation parsing returned null");
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



	// $ANTLR start "family_or_operand_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:775:1: family_or_operand_symbol[String purpose] returns [Tree value] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final Tree family_or_operand_symbol(String purpose) throws RecognitionException {
		Tree value = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:776:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt40=2;
			int LA40_0 = input.LA(1);
			if ( (LA40_0==OP_IDENTIFIER) ) {
				alt40=1;
			}
			else if ( (LA40_0==OP_WILDCARD) ) {
				alt40=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 40, 0, input);
				throw nvae;
			}

			switch (alt40) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:776:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_family_or_operand_symbol2128); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "family or operand", purpose);
								} else if(sym.getType() != symbol_type.value_symbol
										&& sym.getType() != symbol_type.valuemap_symbol
										&& sym.getType() != symbol_type.context_symbol
										&& sym.getType() != symbol_type.name_symbol
										&& sym.getType() != symbol_type.varnodelist_symbol
										&& sym.getType() != symbol_type.operand_symbol) {
									wrongSymbolTypeError(sym, find(s), "family or operand", purpose);
								} else {
									value = s;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:791:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_family_or_operand_symbol2142); 

								wildcardError(t, purpose);
							
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
	// $ANTLR end "family_or_operand_symbol"



	// $ANTLR start "pequation_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:796:1: pequation_symbol[String purpose] returns [PatternEquation value] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final PatternEquation pequation_symbol(String purpose) throws RecognitionException {
		PatternEquation value = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:797:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
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
					// ghidra/sleigh/grammar/SleighCompiler.g:797:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_pequation_symbol2161); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								Location location = find(s);
								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "family, operand, epsilon, or subtable", purpose);
								} else if(sym.getType() == symbol_type.value_symbol
										|| sym.getType() == symbol_type.valuemap_symbol
										|| sym.getType() == symbol_type.context_symbol
										|| sym.getType() == symbol_type.name_symbol
										|| sym.getType() == symbol_type.varnodelist_symbol) {
									value = sc.defineInvisibleOperand(location, (FamilySymbol) sym);
								} else if(sym.getType() == symbol_type.operand_symbol) {
									OperandSymbol os = (OperandSymbol) sym;
									value = new OperandEquation(location, os.getIndex()); sc.selfDefine(os);
								} else if(sym.getType() == symbol_type.epsilon_symbol) {
									SpecificSymbol ss = (SpecificSymbol) sym;
									value = new UnconstrainedEquation(location, ss.getPatternExpression());
								} else if(sym.getType() == symbol_type.subtable_symbol) {
									SubtableSymbol ss = (SubtableSymbol) sym;
									value = sc.defineInvisibleOperand(location, ss);
								} else {
									value = null;
									wrongSymbolTypeError(sym, find(s), "family, operand, epsilon, or subtable", purpose);
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:822:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_pequation_symbol2175); 

								wildcardError(t, purpose);
							
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
	// $ANTLR end "pequation_symbol"



	// $ANTLR start "pexpression"
	// ghidra/sleigh/grammar/SleighCompiler.g:827:1: pexpression returns [PatternExpression value] : ( ^(t= OP_OR l= pexpression r= pexpression ) | ^(t= OP_XOR l= pexpression r= pexpression ) | ^(t= OP_AND l= pexpression r= pexpression ) | ^(t= OP_LEFT l= pexpression r= pexpression ) | ^(t= OP_RIGHT l= pexpression r= pexpression ) | ^(t= OP_ADD l= pexpression r= pexpression ) | ^(t= OP_SUB l= pexpression r= pexpression ) | ^(t= OP_MULT l= pexpression r= pexpression ) | ^(t= OP_DIV l= pexpression r= pexpression ) | ^(t= OP_NEGATE l= pexpression ) | ^(t= OP_INVERT l= pexpression ) |y= pattern_symbol[\"pattern expression\"] |i= integer | ^( OP_PARENTHESIZED l= pexpression ) );
	public final PatternExpression pexpression() throws RecognitionException {
		PatternExpression value = null;


		CommonTree t=null;
		PatternExpression l =null;
		PatternExpression r =null;
		PatternExpression y =null;
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:828:2: ( ^(t= OP_OR l= pexpression r= pexpression ) | ^(t= OP_XOR l= pexpression r= pexpression ) | ^(t= OP_AND l= pexpression r= pexpression ) | ^(t= OP_LEFT l= pexpression r= pexpression ) | ^(t= OP_RIGHT l= pexpression r= pexpression ) | ^(t= OP_ADD l= pexpression r= pexpression ) | ^(t= OP_SUB l= pexpression r= pexpression ) | ^(t= OP_MULT l= pexpression r= pexpression ) | ^(t= OP_DIV l= pexpression r= pexpression ) | ^(t= OP_NEGATE l= pexpression ) | ^(t= OP_INVERT l= pexpression ) |y= pattern_symbol[\"pattern expression\"] |i= integer | ^( OP_PARENTHESIZED l= pexpression ) )
			int alt42=14;
			switch ( input.LA(1) ) {
			case OP_OR:
				{
				alt42=1;
				}
				break;
			case OP_XOR:
				{
				alt42=2;
				}
				break;
			case OP_AND:
				{
				alt42=3;
				}
				break;
			case OP_LEFT:
				{
				alt42=4;
				}
				break;
			case OP_RIGHT:
				{
				alt42=5;
				}
				break;
			case OP_ADD:
				{
				alt42=6;
				}
				break;
			case OP_SUB:
				{
				alt42=7;
				}
				break;
			case OP_MULT:
				{
				alt42=8;
				}
				break;
			case OP_DIV:
				{
				alt42=9;
				}
				break;
			case OP_NEGATE:
				{
				alt42=10;
				}
				break;
			case OP_INVERT:
				{
				alt42=11;
				}
				break;
			case OP_IDENTIFIER:
			case OP_WILDCARD:
				{
				alt42=12;
				}
				break;
			case OP_BIN_CONSTANT:
			case OP_DEC_CONSTANT:
			case OP_HEX_CONSTANT:
				{
				alt42=13;
				}
				break;
			case OP_PARENTHESIZED:
				{
				alt42=14;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 42, 0, input);
				throw nvae;
			}
			switch (alt42) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:828:4: ^(t= OP_OR l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_OR,FOLLOW_OP_OR_in_pexpression2195); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2199);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2203);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new OrExpression(find(t), l, r); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:829:4: ^(t= OP_XOR l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_XOR,FOLLOW_OP_XOR_in_pexpression2214); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2218);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2222);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new XorExpression(find(t), l, r); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:830:4: ^(t= OP_AND l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_AND,FOLLOW_OP_AND_in_pexpression2233); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2237);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2241);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new AndExpression(find(t), l, r); 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:831:4: ^(t= OP_LEFT l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_LEFT,FOLLOW_OP_LEFT_in_pexpression2252); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2256);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2260);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new LeftShiftExpression(find(t), l, r); 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:832:4: ^(t= OP_RIGHT l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_RIGHT,FOLLOW_OP_RIGHT_in_pexpression2271); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2275);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2279);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new RightShiftExpression(find(t), l, r); 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:833:4: ^(t= OP_ADD l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_ADD,FOLLOW_OP_ADD_in_pexpression2290); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2294);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2298);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new PlusExpression(find(t), l, r); 
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:834:4: ^(t= OP_SUB l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_SUB,FOLLOW_OP_SUB_in_pexpression2309); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2313);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2317);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new SubExpression(find(t), l, r); 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighCompiler.g:835:4: ^(t= OP_MULT l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_MULT,FOLLOW_OP_MULT_in_pexpression2328); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2332);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2336);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new MultExpression(find(t), l, r); 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighCompiler.g:836:4: ^(t= OP_DIV l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_DIV,FOLLOW_OP_DIV_in_pexpression2347); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2351);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2355);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new DivExpression(find(t), l, r); 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighCompiler.g:838:4: ^(t= OP_NEGATE l= pexpression )
					{
					t=(CommonTree)match(input,OP_NEGATE,FOLLOW_OP_NEGATE_in_pexpression2367); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2371);
					l=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new MinusExpression(find(t), l); 
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighCompiler.g:839:4: ^(t= OP_INVERT l= pexpression )
					{
					t=(CommonTree)match(input,OP_INVERT,FOLLOW_OP_INVERT_in_pexpression2382); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2386);
					l=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new NotExpression(find(t), l); 
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighCompiler.g:842:4: y= pattern_symbol[\"pattern expression\"]
					{
					pushFollow(FOLLOW_pattern_symbol_in_pexpression2398);
					y=pattern_symbol("pattern expression");
					state._fsp--;

					 value = y; 
					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighCompiler.g:843:4: i= integer
					{
					pushFollow(FOLLOW_integer_in_pexpression2408);
					i=integer();
					state._fsp--;

					 value = new ConstantValue(i.location, toLong(i)); 
					}
					break;
				case 14 :
					// ghidra/sleigh/grammar/SleighCompiler.g:844:4: ^( OP_PARENTHESIZED l= pexpression )
					{
					match(input,OP_PARENTHESIZED,FOLLOW_OP_PARENTHESIZED_in_pexpression2416); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2420);
					l=pexpression();
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
	// $ANTLR end "pexpression"



	// $ANTLR start "pexpression2"
	// ghidra/sleigh/grammar/SleighCompiler.g:847:1: pexpression2 returns [PatternExpression value] : ( ^(t= OP_OR l= pexpression2 r= pexpression2 ) | ^(t= OP_XOR l= pexpression2 r= pexpression2 ) | ^(t= OP_AND l= pexpression2 r= pexpression2 ) | ^(t= OP_LEFT l= pexpression2 r= pexpression2 ) | ^(t= OP_RIGHT l= pexpression2 r= pexpression2 ) | ^(t= OP_ADD l= pexpression2 r= pexpression2 ) | ^(t= OP_SUB l= pexpression2 r= pexpression2 ) | ^(t= OP_MULT l= pexpression2 r= pexpression2 ) | ^(t= OP_DIV l= pexpression2 r= pexpression2 ) | ^(t= OP_NEGATE l= pexpression2 ) | ^(t= OP_INVERT l= pexpression2 ) |y= pattern_symbol2[\"pattern expression\"] |i= integer | ^( OP_PARENTHESIZED l= pexpression2 ) );
	public final PatternExpression pexpression2() throws RecognitionException {
		PatternExpression value = null;


		CommonTree t=null;
		PatternExpression l =null;
		PatternExpression r =null;
		PatternExpression y =null;
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:848:2: ( ^(t= OP_OR l= pexpression2 r= pexpression2 ) | ^(t= OP_XOR l= pexpression2 r= pexpression2 ) | ^(t= OP_AND l= pexpression2 r= pexpression2 ) | ^(t= OP_LEFT l= pexpression2 r= pexpression2 ) | ^(t= OP_RIGHT l= pexpression2 r= pexpression2 ) | ^(t= OP_ADD l= pexpression2 r= pexpression2 ) | ^(t= OP_SUB l= pexpression2 r= pexpression2 ) | ^(t= OP_MULT l= pexpression2 r= pexpression2 ) | ^(t= OP_DIV l= pexpression2 r= pexpression2 ) | ^(t= OP_NEGATE l= pexpression2 ) | ^(t= OP_INVERT l= pexpression2 ) |y= pattern_symbol2[\"pattern expression\"] |i= integer | ^( OP_PARENTHESIZED l= pexpression2 ) )
			int alt43=14;
			switch ( input.LA(1) ) {
			case OP_OR:
				{
				alt43=1;
				}
				break;
			case OP_XOR:
				{
				alt43=2;
				}
				break;
			case OP_AND:
				{
				alt43=3;
				}
				break;
			case OP_LEFT:
				{
				alt43=4;
				}
				break;
			case OP_RIGHT:
				{
				alt43=5;
				}
				break;
			case OP_ADD:
				{
				alt43=6;
				}
				break;
			case OP_SUB:
				{
				alt43=7;
				}
				break;
			case OP_MULT:
				{
				alt43=8;
				}
				break;
			case OP_DIV:
				{
				alt43=9;
				}
				break;
			case OP_NEGATE:
				{
				alt43=10;
				}
				break;
			case OP_INVERT:
				{
				alt43=11;
				}
				break;
			case OP_IDENTIFIER:
			case OP_WILDCARD:
				{
				alt43=12;
				}
				break;
			case OP_BIN_CONSTANT:
			case OP_DEC_CONSTANT:
			case OP_HEX_CONSTANT:
				{
				alt43=13;
				}
				break;
			case OP_PARENTHESIZED:
				{
				alt43=14;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 43, 0, input);
				throw nvae;
			}
			switch (alt43) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:848:4: ^(t= OP_OR l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_OR,FOLLOW_OP_OR_in_pexpression22441); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22445);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22449);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new OrExpression(find(t), l, r); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:849:4: ^(t= OP_XOR l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_XOR,FOLLOW_OP_XOR_in_pexpression22460); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22464);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22468);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new XorExpression(find(t), l, r); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:850:4: ^(t= OP_AND l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_AND,FOLLOW_OP_AND_in_pexpression22479); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22483);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22487);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new AndExpression(find(t), l, r); 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:851:4: ^(t= OP_LEFT l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_LEFT,FOLLOW_OP_LEFT_in_pexpression22498); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22502);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22506);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new LeftShiftExpression(find(t), l, r); 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:852:4: ^(t= OP_RIGHT l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_RIGHT,FOLLOW_OP_RIGHT_in_pexpression22517); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22521);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22525);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new RightShiftExpression(find(t), l, r); 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:853:4: ^(t= OP_ADD l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_ADD,FOLLOW_OP_ADD_in_pexpression22536); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22540);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22544);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new PlusExpression(find(t), l, r); 
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:854:4: ^(t= OP_SUB l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_SUB,FOLLOW_OP_SUB_in_pexpression22555); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22559);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22563);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new SubExpression(find(t), l, r); 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighCompiler.g:855:4: ^(t= OP_MULT l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_MULT,FOLLOW_OP_MULT_in_pexpression22574); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22578);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22582);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new MultExpression(find(t), l, r); 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighCompiler.g:856:4: ^(t= OP_DIV l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_DIV,FOLLOW_OP_DIV_in_pexpression22593); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22597);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22601);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new DivExpression(find(t), l, r); 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighCompiler.g:858:4: ^(t= OP_NEGATE l= pexpression2 )
					{
					t=(CommonTree)match(input,OP_NEGATE,FOLLOW_OP_NEGATE_in_pexpression22613); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22617);
					l=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new MinusExpression(find(t), l); 
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighCompiler.g:859:4: ^(t= OP_INVERT l= pexpression2 )
					{
					t=(CommonTree)match(input,OP_INVERT,FOLLOW_OP_INVERT_in_pexpression22628); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22632);
					l=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new NotExpression(find(t), l); 
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighCompiler.g:862:4: y= pattern_symbol2[\"pattern expression\"]
					{
					pushFollow(FOLLOW_pattern_symbol2_in_pexpression22644);
					y=pattern_symbol2("pattern expression");
					state._fsp--;

					 value = y; 
					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighCompiler.g:863:4: i= integer
					{
					pushFollow(FOLLOW_integer_in_pexpression22654);
					i=integer();
					state._fsp--;

					 value = new ConstantValue(i.location, toLong(i)); 
					}
					break;
				case 14 :
					// ghidra/sleigh/grammar/SleighCompiler.g:864:4: ^( OP_PARENTHESIZED l= pexpression2 )
					{
					match(input,OP_PARENTHESIZED,FOLLOW_OP_PARENTHESIZED_in_pexpression22662); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22666);
					l=pexpression2();
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
	// $ANTLR end "pexpression2"



	// $ANTLR start "pattern_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:867:1: pattern_symbol[String purpose] returns [PatternExpression expr] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final PatternExpression pattern_symbol(String purpose) throws RecognitionException {
		PatternExpression expr = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:868:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt44=2;
			int LA44_0 = input.LA(1);
			if ( (LA44_0==OP_IDENTIFIER) ) {
				alt44=1;
			}
			else if ( (LA44_0==OP_WILDCARD) ) {
				alt44=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 44, 0, input);
				throw nvae;
			}

			switch (alt44) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:868:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_pattern_symbol2686); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "start, end, next2, operand, epsilon, or varnode", purpose);
					            } else if(sym.getType() == symbol_type.operand_symbol) {
					                OperandSymbol os = (OperandSymbol) sym;
					                if (os.getDefiningSymbol() != null && os.getDefiningSymbol().getType() == symbol_type.subtable_symbol) {
					                    reportError(find(s), "Subtable symbol '" + sym.getName() + "' is not allowed in context block");
					                }
					                expr = os.getPatternExpression();
								} else if(sym.getType() == symbol_type.start_symbol
										|| sym.getType() == symbol_type.end_symbol
										|| sym.getType() == symbol_type.next2_symbol
										|| sym.getType() == symbol_type.flowdest_symbol
										|| sym.getType() == symbol_type.flowref_symbol
										|| sym.getType() == symbol_type.epsilon_symbol
										|| sym.getType() == symbol_type.varnode_symbol) {
									SpecificSymbol ss = (SpecificSymbol) sym;
									expr = ss.getPatternExpression();
								} else if(sym.getType() == symbol_type.value_symbol
										|| sym.getType() == symbol_type.valuemap_symbol
										|| sym.getType() == symbol_type.context_symbol
										|| sym.getType() == symbol_type.name_symbol
										|| sym.getType() == symbol_type.varnodelist_symbol) {
									if (sym.getType() == symbol_type.context_symbol) {
										FamilySymbol z = (FamilySymbol) sym;
										expr = z.getPatternValue();
									} else {
										reportError(find(s), "Global symbol '" + sym.getName() + "' is not allowed in action expression");
									}
								} else {
									wrongSymbolTypeError(sym, find(s), "start, end, next2, operand, epsilon, or varnode", purpose);
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:902:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_pattern_symbol2700); 

								wildcardError(t, purpose);
								expr = null;
							
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
		return expr;
	}
	// $ANTLR end "pattern_symbol"



	// $ANTLR start "pattern_symbol2"
	// ghidra/sleigh/grammar/SleighCompiler.g:908:1: pattern_symbol2[String purpose] returns [PatternExpression expr] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final PatternExpression pattern_symbol2(String purpose) throws RecognitionException {
		PatternExpression expr = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:909:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt45=2;
			int LA45_0 = input.LA(1);
			if ( (LA45_0==OP_IDENTIFIER) ) {
				alt45=1;
			}
			else if ( (LA45_0==OP_WILDCARD) ) {
				alt45=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 45, 0, input);
				throw nvae;
			}

			switch (alt45) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:909:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_pattern_symbol22719); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "start, end, next2, operand, epsilon, or varnode", purpose);
								} else if(sym.getType() == symbol_type.start_symbol
										|| sym.getType() == symbol_type.end_symbol
										|| sym.getType() == symbol_type.next2_symbol
										|| sym.getType() == symbol_type.flowdest_symbol
										|| sym.getType() == symbol_type.flowref_symbol
										|| sym.getType() == symbol_type.operand_symbol
										|| sym.getType() == symbol_type.epsilon_symbol
										|| sym.getType() == symbol_type.varnode_symbol) {
									SpecificSymbol ss = (SpecificSymbol) sym;
									expr = ss.getPatternExpression();
								} else if(sym.getType() == symbol_type.value_symbol
										|| sym.getType() == symbol_type.valuemap_symbol
										|| sym.getType() == symbol_type.context_symbol
										|| sym.getType() == symbol_type.name_symbol
										|| sym.getType() == symbol_type.varnodelist_symbol) {
									FamilySymbol z = (FamilySymbol) sym;
									expr = z.getPatternValue();
								} else {
									wrongSymbolTypeError(sym, find(s), "start, end, next2, operand, epsilon, or varnode", purpose);
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:934:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_pattern_symbol22733); 

								wildcardError(t, purpose);
								expr = null;
							
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
		return expr;
	}
	// $ANTLR end "pattern_symbol2"



	// $ANTLR start "contextblock"
	// ghidra/sleigh/grammar/SleighCompiler.g:940:1: contextblock returns [VectorSTL<ContextChange> value] : ( ^( OP_CONTEXT_BLOCK r= cstatements ) | OP_NO_CONTEXT_BLOCK );
	public final VectorSTL<ContextChange> contextblock() throws RecognitionException {
		VectorSTL<ContextChange> value = null;


		VectorSTL<ContextChange> r =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:941:2: ( ^( OP_CONTEXT_BLOCK r= cstatements ) | OP_NO_CONTEXT_BLOCK )
			int alt46=2;
			int LA46_0 = input.LA(1);
			if ( (LA46_0==OP_CONTEXT_BLOCK) ) {
				alt46=1;
			}
			else if ( (LA46_0==OP_NO_CONTEXT_BLOCK) ) {
				alt46=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 46, 0, input);
				throw nvae;
			}

			switch (alt46) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:941:4: ^( OP_CONTEXT_BLOCK r= cstatements )
					{
					match(input,OP_CONTEXT_BLOCK,FOLLOW_OP_CONTEXT_BLOCK_in_contextblock2751); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_cstatements_in_contextblock2755);
					r=cstatements();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = r; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:942:4: OP_NO_CONTEXT_BLOCK
					{
					match(input,OP_NO_CONTEXT_BLOCK,FOLLOW_OP_NO_CONTEXT_BLOCK_in_contextblock2763); 
					 value = null; 
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
	// $ANTLR end "contextblock"



	// $ANTLR start "cstatements"
	// ghidra/sleigh/grammar/SleighCompiler.g:945:1: cstatements returns [VectorSTL<ContextChange> r] : ( cstatement[r] )+ ;
	public final VectorSTL<ContextChange> cstatements() throws RecognitionException {
		VectorSTL<ContextChange> r = null;



				r = new VectorSTL<ContextChange>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:949:2: ( ( cstatement[r] )+ )
			// ghidra/sleigh/grammar/SleighCompiler.g:949:4: ( cstatement[r] )+
			{
			// ghidra/sleigh/grammar/SleighCompiler.g:949:4: ( cstatement[r] )+
			int cnt47=0;
			loop47:
			while (true) {
				int alt47=2;
				int LA47_0 = input.LA(1);
				if ( (LA47_0==OP_APPLY||LA47_0==OP_ASSIGN) ) {
					alt47=1;
				}

				switch (alt47) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:949:4: cstatement[r]
					{
					pushFollow(FOLLOW_cstatement_in_cstatements2785);
					cstatement(r);
					state._fsp--;

					}
					break;

				default :
					if ( cnt47 >= 1 ) break loop47;
					EarlyExitException eee = new EarlyExitException(47, input);
					throw eee;
				}
				cnt47++;
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
		return r;
	}
	// $ANTLR end "cstatements"



	// $ANTLR start "cstatement"
	// ghidra/sleigh/grammar/SleighCompiler.g:952:1: cstatement[VectorSTL<ContextChange> r] : ( ^( OP_ASSIGN ^( OP_IDENTIFIER id= . ) e= pexpression ) | ^( OP_APPLY ^( OP_IDENTIFIER id= . ) ^( OP_IDENTIFIER arg1= . ) ^( OP_IDENTIFIER arg2= . ) ) );
	public final void cstatement(VectorSTL<ContextChange> r) throws RecognitionException {
		CommonTree id=null;
		CommonTree arg1=null;
		CommonTree arg2=null;
		PatternExpression e =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:953:2: ( ^( OP_ASSIGN ^( OP_IDENTIFIER id= . ) e= pexpression ) | ^( OP_APPLY ^( OP_IDENTIFIER id= . ) ^( OP_IDENTIFIER arg1= . ) ^( OP_IDENTIFIER arg2= . ) ) )
			int alt48=2;
			int LA48_0 = input.LA(1);
			if ( (LA48_0==OP_ASSIGN) ) {
				alt48=1;
			}
			else if ( (LA48_0==OP_APPLY) ) {
				alt48=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 48, 0, input);
				throw nvae;
			}

			switch (alt48) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:953:4: ^( OP_ASSIGN ^( OP_IDENTIFIER id= . ) e= pexpression )
					{
					match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_cstatement2800); 
					match(input, Token.DOWN, null); 
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_cstatement2803); 
					match(input, Token.DOWN, null); 
					id=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					pushFollow(FOLLOW_pexpression_in_cstatement2812);
					e=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(id.getText());
								if (sym == null) {
									unknownSymbolError(id.getText(), find(id), "context or operand", "context block lvalue");
								} else if(sym.getType() == symbol_type.context_symbol) {
									ContextSymbol t = (ContextSymbol) sym;
									if (!sc.contextMod(r, t, e)) {
										reportError(find(id), "Cannot use 'inst_next' or 'inst_next2' to set context variable: '" + t.getName() + "'");
									}
								} else if(sym.getType() == symbol_type.operand_symbol) {
									OperandSymbol t = (OperandSymbol) sym;
									sc.defineOperand(find(id), t, e);
								} else {
									wrongSymbolTypeError(sym, find(id), "context or operand", "context block lvalue");
								}	
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:969:4: ^( OP_APPLY ^( OP_IDENTIFIER id= . ) ^( OP_IDENTIFIER arg1= . ) ^( OP_IDENTIFIER arg2= . ) )
					{
					match(input,OP_APPLY,FOLLOW_OP_APPLY_in_cstatement2821); 
					match(input, Token.DOWN, null); 
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_cstatement2824); 
					match(input, Token.DOWN, null); 
					id=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_cstatement2832); 
					match(input, Token.DOWN, null); 
					arg1=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_cstatement2840); 
					match(input, Token.DOWN, null); 
					arg2=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					match(input, Token.UP, null); 


								if (!"globalset".equals(id.getText())) {
									reportError(find(id), "unknown context block function '" + id.getText() + "'");
								} else {
									SleighSymbol sym = sc.findSymbol(arg2.getText());
									if (sym == null) {
										unknownSymbolError(arg2.getText(), find(arg2), "context", "globalset call");
									} else if(sym.getType() == symbol_type.context_symbol) {
										ContextSymbol t = (ContextSymbol) sym;
										sym = sc.findSymbol(arg1.getText());
										if (sym == null) {
											unknownSymbolError(arg1.getText(), find(arg1), "family or specific", "globalset call");
										} else if(sym.getType() == symbol_type.value_symbol
												|| sym.getType() == symbol_type.valuemap_symbol
												|| sym.getType() == symbol_type.context_symbol
												|| sym.getType() == symbol_type.name_symbol
												|| sym.getType() == symbol_type.varnodelist_symbol
												|| sym.getType() == symbol_type.start_symbol
												|| sym.getType() == symbol_type.end_symbol
												|| sym.getType() == symbol_type.next2_symbol
												|| sym.getType() == symbol_type.flowdest_symbol
												|| sym.getType() == symbol_type.flowref_symbol
												|| sym.getType() == symbol_type.operand_symbol
												|| sym.getType() == symbol_type.epsilon_symbol
												|| sym.getType() == symbol_type.varnode_symbol) {
											sc.contextSet(r, (TripleSymbol) sym, t);
										} else {
											wrongSymbolTypeError(sym, find(arg1), "family or specific", "globalset call");
										}
									} else {
										wrongSymbolTypeError(sym, find(arg2), "context", "globalset call");
									}
								}
							
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
	// $ANTLR end "cstatement"


	protected static class semantic_scope {
		SectionVector sections;
		boolean containsMultipleSections;
		boolean nextStatementMustBeSectionLabel;
		boolean canContainSections;
	}
	protected Stack<semantic_scope> semantic_stack = new Stack<semantic_scope>();


	// $ANTLR start "semantic"
	// ghidra/sleigh/grammar/SleighCompiler.g:1005:1: semantic[ParsingEnvironment pe, Location containerLoc, PcodeCompile pcode, Tree where, boolean sectionsAllowed, boolean isMacroParse] returns [SectionVector rtl] : ^(x= OP_SEMANTIC c= code_block[find($x)] ) ;
	public final SectionVector semantic(ParsingEnvironment pe, Location containerLoc, PcodeCompile pcode, Tree where, boolean sectionsAllowed, boolean isMacroParse) throws RecognitionException {
		semantic_stack.push(new semantic_scope());
		SectionVector rtl = null;


		CommonTree x=null;
		ConstructTpl c =null;


				ParsingEnvironment oldEnv = this.env;
				SleighCompile oldSC = sc;
				sc = null; // TODO: force failure with improper use of sc instead of pcode
				this.env = pe;
				this.pcode = pcode;
				
				semantic_stack.peek().sections = null;
				semantic_stack.peek().containsMultipleSections = false;
				semantic_stack.peek().nextStatementMustBeSectionLabel = false;
				semantic_stack.peek().canContainSections = sectionsAllowed;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1027:2: ( ^(x= OP_SEMANTIC c= code_block[find($x)] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1027:4: ^(x= OP_SEMANTIC c= code_block[find($x)] )
			{
			x=(CommonTree)match(input,OP_SEMANTIC,FOLLOW_OP_SEMANTIC_in_semantic2884); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				pushFollow(FOLLOW_code_block_in_semantic2888);
				c=code_block(find(x));
				state._fsp--;


							if (c != null) {
								if (c.getOpvec().empty() && c.getResult() == null) {
								    Location loc = find(where);
								    if (loc == null) {
								       loc = containerLoc;
								    }
									pcode.recordNop(loc);
								}
								if (semantic_stack.peek().containsMultipleSections) {
									semantic_stack.peek().sections = pcode.finalNamedSection(semantic_stack.peek().sections, c);
								} else {
									if (!isMacroParse) {
										semantic_stack.peek().sections = pcode.standaloneSection(c);
									} else {
										macrodef_stack.peek().macrobody = c;
									}
								}
							}
						
				match(input, Token.UP, null); 
			}

			}


					rtl = semantic_stack.peek().sections;
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			semantic_stack.pop();

				   this.sc = oldSC;
				   this.env = oldEnv;
				   this.pcode = null;
				
		}
		return rtl;
	}
	// $ANTLR end "semantic"


	protected static class code_block_scope {
		Location stmtLocation;
	}
	protected Stack<code_block_scope> code_block_stack = new Stack<code_block_scope>();


	// $ANTLR start "code_block"
	// ghidra/sleigh/grammar/SleighCompiler.g:1055:1: code_block[Location startingPoint] returns [ConstructTpl rtl] : ( statements | OP_NOP );
	public final ConstructTpl code_block(Location startingPoint) throws RecognitionException {
		Block_stack.push(new Block_scope());
		code_block_stack.push(new code_block_scope());
		ConstructTpl rtl = null;



				Block_stack.peek().ct = pcode.enterSection(startingPoint);
				code_block_stack.peek().stmtLocation = new Location("<internal error populating statement location>", 0);
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1067:2: ( statements | OP_NOP )
			int alt49=2;
			int LA49_0 = input.LA(1);
			if ( (LA49_0==UP||LA49_0==OP_APPLY||LA49_0==OP_ASSIGN||(LA49_0 >= OP_BUILD && LA49_0 <= OP_CALL)||LA49_0==OP_CROSSBUILD||LA49_0==OP_EXPORT||LA49_0==OP_GOTO||LA49_0==OP_IF||LA49_0==OP_LABEL||LA49_0==OP_LOCAL||LA49_0==OP_RETURN||LA49_0==OP_SECTION_LABEL) ) {
				alt49=1;
			}
			else if ( (LA49_0==OP_NOP) ) {
				alt49=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 49, 0, input);
				throw nvae;
			}

			switch (alt49) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1067:4: statements
					{
					pushFollow(FOLLOW_statements_in_code_block2939);
					statements();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1068:4: OP_NOP
					{
					match(input,OP_NOP,FOLLOW_OP_NOP_in_code_block2944); 
					}
					break;

			}

					rtl = Block_stack.peek().ct;
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			Block_stack.pop();
			code_block_stack.pop();
		}
		return rtl;
	}
	// $ANTLR end "code_block"



	// $ANTLR start "statements"
	// ghidra/sleigh/grammar/SleighCompiler.g:1071:1: statements : ( statement )* ;
	public final void statements() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1072:2: ( ( statement )* )
			// ghidra/sleigh/grammar/SleighCompiler.g:1072:4: ( statement )*
			{
			// ghidra/sleigh/grammar/SleighCompiler.g:1072:4: ( statement )*
			loop50:
			while (true) {
				int alt50=2;
				int LA50_0 = input.LA(1);
				if ( (LA50_0==OP_APPLY||LA50_0==OP_ASSIGN||(LA50_0 >= OP_BUILD && LA50_0 <= OP_CALL)||LA50_0==OP_CROSSBUILD||LA50_0==OP_EXPORT||LA50_0==OP_GOTO||LA50_0==OP_IF||LA50_0==OP_LABEL||LA50_0==OP_LOCAL||LA50_0==OP_RETURN||LA50_0==OP_SECTION_LABEL) ) {
					alt50=1;
				}

				switch (alt50) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1072:4: statement
					{
					pushFollow(FOLLOW_statement_in_statements2955);
					statement();
					state._fsp--;

					}
					break;

				default :
					break loop50;
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



	// $ANTLR start "statement"
	// ghidra/sleigh/grammar/SleighCompiler.g:1075:1: statement : (r= assignment | declaration |r= funcall |r= build_stmt |r= crossbuild_stmt |r= goto_stmt |r= cond_stmt |r= call_stmt |r= return_stmt |l= label |e= export[$Block::ct] |s= section_label );
	public final void statement() throws RecognitionException {
		Return_stack.push(new Return_scope());

		VectorSTL<OpTpl> r =null;
		Pair<Location,LabelSymbol> l =null;
		ConstructTpl e =null;
		Pair<Location,SectionSymbol> s =null;


				VectorSTL<OpTpl> ops = new VectorSTL<OpTpl>();
				Return_stack.peek().noReturn = false;
				boolean wasSectionLabel = false;
				boolean lookingForSectionLabel = semantic_stack.peek().nextStatementMustBeSectionLabel;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1092:2: (r= assignment | declaration |r= funcall |r= build_stmt |r= crossbuild_stmt |r= goto_stmt |r= cond_stmt |r= call_stmt |r= return_stmt |l= label |e= export[$Block::ct] |s= section_label )
			int alt51=12;
			switch ( input.LA(1) ) {
			case OP_ASSIGN:
				{
				alt51=1;
				}
				break;
			case OP_LOCAL:
				{
				int LA51_2 = input.LA(2);
				if ( (LA51_2==DOWN) ) {
					int LA51_13 = input.LA(3);
					if ( (LA51_13==OP_ASSIGN) ) {
						alt51=1;
					}
					else if ( (LA51_13==OP_IDENTIFIER||LA51_13==OP_WILDCARD) ) {
						alt51=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 51, 13, input);
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
							new NoViableAltException("", 51, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case OP_APPLY:
				{
				alt51=3;
				}
				break;
			case OP_BUILD:
				{
				alt51=4;
				}
				break;
			case OP_CROSSBUILD:
				{
				alt51=5;
				}
				break;
			case OP_GOTO:
				{
				alt51=6;
				}
				break;
			case OP_IF:
				{
				alt51=7;
				}
				break;
			case OP_CALL:
				{
				alt51=8;
				}
				break;
			case OP_RETURN:
				{
				alt51=9;
				}
				break;
			case OP_LABEL:
				{
				alt51=10;
				}
				break;
			case OP_EXPORT:
				{
				alt51=11;
				}
				break;
			case OP_SECTION_LABEL:
				{
				alt51=12;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 51, 0, input);
				throw nvae;
			}
			switch (alt51) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1092:4: r= assignment
					{
					pushFollow(FOLLOW_assignment_in_statement2987);
					r=assignment();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1093:4: declaration
					{
					pushFollow(FOLLOW_declaration_in_statement2999);
					declaration();
					state._fsp--;

					 ops = null; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1094:4: r= funcall
					{
					pushFollow(FOLLOW_funcall_in_statement3011);
					r=funcall();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1095:4: r= build_stmt
					{
					pushFollow(FOLLOW_build_stmt_in_statement3028);
					r=build_stmt();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1096:4: r= crossbuild_stmt
					{
					pushFollow(FOLLOW_crossbuild_stmt_in_statement3042);
					r=crossbuild_stmt();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1097:4: r= goto_stmt
					{
					pushFollow(FOLLOW_goto_stmt_in_statement3051);
					r=goto_stmt();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1098:4: r= cond_stmt
					{
					pushFollow(FOLLOW_cond_stmt_in_statement3066);
					r=cond_stmt();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1099:4: r= call_stmt
					{
					pushFollow(FOLLOW_call_stmt_in_statement3081);
					r=call_stmt();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1100:4: r= return_stmt
					{
					pushFollow(FOLLOW_return_stmt_in_statement3096);
					r=return_stmt();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1101:4: l= label
					{
					pushFollow(FOLLOW_label_in_statement3109);
					l=label();
					state._fsp--;


								if (l != null) {
									ops = pcode.placeLabel(l.first, l.second);
								}
							
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1106:4: e= export[$Block::ct]
					{
					pushFollow(FOLLOW_export_in_statement3118);
					e=export(Block_stack.peek().ct);
					state._fsp--;


								if (semantic_stack.peek().containsMultipleSections) {
									reportError(code_block_stack.peek().stmtLocation, "Export only allowed in default section");
								}
								Block_stack.peek().ct = e;
								semantic_stack.peek().nextStatementMustBeSectionLabel = true;
							
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1113:4: s= section_label
					{
					pushFollow(FOLLOW_section_label_in_statement3128);
					s=section_label();
					state._fsp--;


								if(!semantic_stack.peek().canContainSections) {
									reportError(code_block_stack.peek().stmtLocation, "No sections allowed");
								}
								wasSectionLabel = true;
								if (semantic_stack.peek().containsMultipleSections) {
									semantic_stack.peek().sections = pcode.nextNamedSection(semantic_stack.peek().sections, Block_stack.peek().ct, s.second);
								} else {
									semantic_stack.peek().sections = pcode.firstNamedSection(Block_stack.peek().ct, s.second);
								}
								if (Block_stack.peek().ct.getOpvec().empty() && Block_stack.peek().ct.getResult() == null) {
										pcode.recordNop(s.first);
								}
								semantic_stack.peek().containsMultipleSections = true;
								Block_stack.peek().ct = pcode.enterSection(s.first);
							
					}
					break;

			}

					if (lookingForSectionLabel && !wasSectionLabel) {
						reportError(code_block_stack.peek().stmtLocation, "No statements allowed after export");
					}
					semantic_stack.peek().nextStatementMustBeSectionLabel = false;
					if (ops != null && !Block_stack.peek().ct.addOpList(ops)) {
						reportError(code_block_stack.peek().stmtLocation, "Multiple delayslot declarations");
					}
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			Return_stack.pop();

		}
	}
	// $ANTLR end "statement"



	// $ANTLR start "declaration"
	// ghidra/sleigh/grammar/SleighCompiler.g:1131:1: declaration : ( ^( OP_LOCAL n= unbound_identifier[\"sized local declaration\"] i= integer ) | ^( OP_LOCAL n= unbound_identifier[\"local declaration\"] ) );
	public final void declaration() throws RecognitionException {
		Tree n =null;
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1132:2: ( ^( OP_LOCAL n= unbound_identifier[\"sized local declaration\"] i= integer ) | ^( OP_LOCAL n= unbound_identifier[\"local declaration\"] ) )
			int alt52=2;
			alt52 = dfa52.predict(input);
			switch (alt52) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1132:4: ^( OP_LOCAL n= unbound_identifier[\"sized local declaration\"] i= integer )
					{
					match(input,OP_LOCAL,FOLLOW_OP_LOCAL_in_declaration3142); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_unbound_identifier_in_declaration3146);
					n=unbound_identifier("sized local declaration");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_declaration3151);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 


								pcode.newLocalDefinition(find(n), n.getText(), toUInt(i));
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1135:4: ^( OP_LOCAL n= unbound_identifier[\"local declaration\"] )
					{
					match(input,OP_LOCAL,FOLLOW_OP_LOCAL_in_declaration3160); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_unbound_identifier_in_declaration3164);
					n=unbound_identifier("local declaration");
					state._fsp--;

					match(input, Token.UP, null); 


								pcode.newLocalDefinition(find(n), n.getText());
							
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



	// $ANTLR start "label"
	// ghidra/sleigh/grammar/SleighCompiler.g:1140:1: label returns [Pair<Location,LabelSymbol> result] : ^( OP_LABEL ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) ) ;
	public final Pair<Location,LabelSymbol> label() throws RecognitionException {
		Pair<Location,LabelSymbol> result = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1141:2: ( ^( OP_LABEL ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1141:4: ^( OP_LABEL ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) )
			{
			match(input,OP_LABEL,FOLLOW_OP_LABEL_in_label3184); 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighCompiler.g:1141:15: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt53=2;
			int LA53_0 = input.LA(1);
			if ( (LA53_0==OP_IDENTIFIER) ) {
				alt53=1;
			}
			else if ( (LA53_0==OP_WILDCARD) ) {
				alt53=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 53, 0, input);
				throw nvae;
			}

			switch (alt53) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1141:16: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_label3188); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


										SleighSymbol sym = pcode.findSymbol(s.getText());
										if (sym != null) {
											if(sym.getType() != symbol_type.label_symbol) {
												wrongSymbolTypeError(sym, find(s), "label", "label");
											} else {
												result = new Pair<Location,LabelSymbol>(find(s), (LabelSymbol) sym);
											}
										} else {
											Location where = find(s);
											result = new Pair<Location,LabelSymbol>(where, pcode.defineLabel(where, s.getText()));
										}
									
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1154:6: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_label3204); 

										wildcardError(t, "label");
									
					}
					break;

			}

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
		return result;
	}
	// $ANTLR end "label"



	// $ANTLR start "section_label"
	// ghidra/sleigh/grammar/SleighCompiler.g:1159:1: section_label returns [Pair<Location,SectionSymbol> result] : ^( OP_SECTION_LABEL ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) ) ;
	public final Pair<Location,SectionSymbol> section_label() throws RecognitionException {
		Pair<Location,SectionSymbol> result = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1160:2: ( ^( OP_SECTION_LABEL ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1160:4: ^( OP_SECTION_LABEL ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) )
			{
			match(input,OP_SECTION_LABEL,FOLLOW_OP_SECTION_LABEL_in_section_label3224); 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighCompiler.g:1160:23: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt54=2;
			int LA54_0 = input.LA(1);
			if ( (LA54_0==OP_IDENTIFIER) ) {
				alt54=1;
			}
			else if ( (LA54_0==OP_WILDCARD) ) {
				alt54=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 54, 0, input);
				throw nvae;
			}

			switch (alt54) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1160:24: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_section_label3228); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


										SleighSymbol sym = pcode.findSymbol(s.getText());
										if (sym != null) {
											if(sym.getType() != symbol_type.section_symbol) {
												wrongSymbolTypeError(sym, find(s), "section", "section");
											} else {
												result = new Pair<Location,SectionSymbol>(find(s), (SectionSymbol) sym);
											}
										} else {
											Location where = find(s);
											result = new Pair<Location,SectionSymbol>(where, pcode.newSectionSymbol(where, s.getText()));
										}
									
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1173:6: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_section_label3244); 

										wildcardError(t, "section");
									
					}
					break;

			}

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
		return result;
	}
	// $ANTLR end "section_label"



	// $ANTLR start "section_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:1178:1: section_symbol[String purpose] returns [SectionSymbol value] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final SectionSymbol section_symbol(String purpose) throws RecognitionException {
		SectionSymbol value = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1179:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt55=2;
			int LA55_0 = input.LA(1);
			if ( (LA55_0==OP_IDENTIFIER) ) {
				alt55=1;
			}
			else if ( (LA55_0==OP_WILDCARD) ) {
				alt55=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 55, 0, input);
				throw nvae;
			}

			switch (alt55) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1179:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_section_symbol3265); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								Location location = find(s);
								SleighSymbol sym = pcode.findSymbol(s.getText());
								if (sym == null) {
									value = pcode.newSectionSymbol(location, s.getText());
								} else if(sym.getType() != symbol_type.section_symbol) {
									wrongSymbolTypeError(sym, find(s), "section", purpose);
								} else {
									value = (SectionSymbol) sym;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1190:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_section_symbol3279); 

								wildcardError(t, purpose);
							
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
	// $ANTLR end "section_symbol"



	// $ANTLR start "assignment"
	// ghidra/sleigh/grammar/SleighCompiler.g:1195:1: assignment returns [VectorSTL<OpTpl> value] : ( ^(t= OP_ASSIGN ^( OP_BITRANGE ss= specific_symbol[\"bit range assignment\"] a= integer b= integer ) e= expr ) | ^(t= OP_ASSIGN ^( OP_DECLARATIVE_SIZE n= unbound_identifier[\"variable declaration/assignment\"] i= integer ) e= expr ) | ^( OP_LOCAL t= OP_ASSIGN ^( OP_DECLARATIVE_SIZE n= unbound_identifier[\"variable declaration/assignment\"] i= integer ) e= expr ) | ^( OP_LOCAL t= OP_ASSIGN n= unbound_identifier[\"variable declaration/assignment\"] e= expr ) | ^(t= OP_ASSIGN ^( OP_IDENTIFIER id= . ) e= expr ) | ^( OP_ASSIGN t= OP_WILDCARD e= expr ) | ^(t= OP_ASSIGN s= sizedstar f= expr ) );
	public final VectorSTL<OpTpl> assignment() throws RecognitionException {
		VectorSTL<OpTpl> value = null;


		CommonTree t=null;
		CommonTree id=null;
		SpecificSymbol ss =null;
		RadixBigInteger a =null;
		RadixBigInteger b =null;
		ExprTree e =null;
		Tree n =null;
		RadixBigInteger i =null;
		Pair<StarQuality, ExprTree> s =null;
		ExprTree f =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1199:2: ( ^(t= OP_ASSIGN ^( OP_BITRANGE ss= specific_symbol[\"bit range assignment\"] a= integer b= integer ) e= expr ) | ^(t= OP_ASSIGN ^( OP_DECLARATIVE_SIZE n= unbound_identifier[\"variable declaration/assignment\"] i= integer ) e= expr ) | ^( OP_LOCAL t= OP_ASSIGN ^( OP_DECLARATIVE_SIZE n= unbound_identifier[\"variable declaration/assignment\"] i= integer ) e= expr ) | ^( OP_LOCAL t= OP_ASSIGN n= unbound_identifier[\"variable declaration/assignment\"] e= expr ) | ^(t= OP_ASSIGN ^( OP_IDENTIFIER id= . ) e= expr ) | ^( OP_ASSIGN t= OP_WILDCARD e= expr ) | ^(t= OP_ASSIGN s= sizedstar f= expr ) )
			int alt56=7;
			int LA56_0 = input.LA(1);
			if ( (LA56_0==OP_ASSIGN) ) {
				int LA56_1 = input.LA(2);
				if ( (LA56_1==DOWN) ) {
					switch ( input.LA(3) ) {
					case OP_BITRANGE:
						{
						alt56=1;
						}
						break;
					case OP_DECLARATIVE_SIZE:
						{
						alt56=2;
						}
						break;
					case OP_IDENTIFIER:
						{
						alt56=5;
						}
						break;
					case OP_WILDCARD:
						{
						alt56=6;
						}
						break;
					case OP_DEREFERENCE:
						{
						alt56=7;
						}
						break;
					default:
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 56, 3, input);
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
							new NoViableAltException("", 56, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}
			else if ( (LA56_0==OP_LOCAL) ) {
				int LA56_2 = input.LA(2);
				if ( (LA56_2==DOWN) ) {
					int LA56_4 = input.LA(3);
					if ( (LA56_4==OP_ASSIGN) ) {
						int LA56_10 = input.LA(4);
						if ( (LA56_10==OP_DECLARATIVE_SIZE) ) {
							alt56=3;
						}
						else if ( (LA56_10==OP_IDENTIFIER||LA56_10==OP_WILDCARD) ) {
							alt56=4;
						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 56, 10, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 56, 4, input);
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
							new NoViableAltException("", 56, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 56, 0, input);
				throw nvae;
			}

			switch (alt56) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1199:4: ^(t= OP_ASSIGN ^( OP_BITRANGE ss= specific_symbol[\"bit range assignment\"] a= integer b= integer ) e= expr )
					{
					t=(CommonTree)match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3305); 
					match(input, Token.DOWN, null); 
					match(input,OP_BITRANGE,FOLLOW_OP_BITRANGE_in_assignment3308); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_specific_symbol_in_assignment3312);
					ss=specific_symbol("bit range assignment");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_assignment3317);
					a=integer();
					state._fsp--;

					pushFollow(FOLLOW_integer_in_assignment3321);
					b=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					pushFollow(FOLLOW_expr_in_assignment3326);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.assignBitRange(find(t), ss.getVarnode(), toUInt(a), toUInt(b), e);	
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1202:4: ^(t= OP_ASSIGN ^( OP_DECLARATIVE_SIZE n= unbound_identifier[\"variable declaration/assignment\"] i= integer ) e= expr )
					{
					t=(CommonTree)match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3337); 
					match(input, Token.DOWN, null); 
					match(input,OP_DECLARATIVE_SIZE,FOLLOW_OP_DECLARATIVE_SIZE_in_assignment3340); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_unbound_identifier_in_assignment3344);
					n=unbound_identifier("variable declaration/assignment");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_assignment3349);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					pushFollow(FOLLOW_expr_in_assignment3354);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.newOutput(find(n), true, e, n.getText(), toUInt(i));
							
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1205:4: ^( OP_LOCAL t= OP_ASSIGN ^( OP_DECLARATIVE_SIZE n= unbound_identifier[\"variable declaration/assignment\"] i= integer ) e= expr )
					{
					match(input,OP_LOCAL,FOLLOW_OP_LOCAL_in_assignment3363); 
					match(input, Token.DOWN, null); 
					t=(CommonTree)match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3367); 
					match(input,OP_DECLARATIVE_SIZE,FOLLOW_OP_DECLARATIVE_SIZE_in_assignment3370); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_unbound_identifier_in_assignment3374);
					n=unbound_identifier("variable declaration/assignment");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_assignment3379);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					pushFollow(FOLLOW_expr_in_assignment3384);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.newOutput(find(n), true, e, n.getText(), toUInt(i));
							
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1208:4: ^( OP_LOCAL t= OP_ASSIGN n= unbound_identifier[\"variable declaration/assignment\"] e= expr )
					{
					match(input,OP_LOCAL,FOLLOW_OP_LOCAL_in_assignment3393); 
					match(input, Token.DOWN, null); 
					t=(CommonTree)match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3397); 
					pushFollow(FOLLOW_unbound_identifier_in_assignment3401);
					n=unbound_identifier("variable declaration/assignment");
					state._fsp--;

					pushFollow(FOLLOW_expr_in_assignment3406);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.newOutput(find(n), true, e, n.getText());
							
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1211:4: ^(t= OP_ASSIGN ^( OP_IDENTIFIER id= . ) e= expr )
					{
					t=(CommonTree)match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3417); 
					match(input, Token.DOWN, null); 
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_assignment3420); 
					match(input, Token.DOWN, null); 
					id=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					pushFollow(FOLLOW_expr_in_assignment3429);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								SleighSymbol sym = pcode.findSymbol(id.getText());
								if (sym == null) {
									value = pcode.newOutput(find(id), false, e, id.getText());
					            } else if (sym instanceof BitrangeSymbol) {
					                BitrangeSymbol bitSym = (BitrangeSymbol)sym;
					                VarnodeSymbol parent = bitSym.getParentSymbol();
					                value = pcode.assignBitRange(find(t), parent.getVarnode(),
					                                              bitSym.getBitOffset(),
					                                              bitSym.numBits(),e);
								} else if(sym.getType() != symbol_type.start_symbol
										&& sym.getType() != symbol_type.end_symbol
										&& sym.getType() != symbol_type.next2_symbol
										&& sym.getType() != symbol_type.flowdest_symbol
										&& sym.getType() != symbol_type.flowref_symbol
										&& sym.getType() != symbol_type.operand_symbol
										&& sym.getType() != symbol_type.epsilon_symbol
										&& sym.getType() != symbol_type.varnode_symbol) {
									wrongSymbolTypeError(sym, find(id), "start, end, next2, operand, epsilon, or varnode", "assignment");
								} else {
									VarnodeTpl v = ((SpecificSymbol) sym).getVarnode();
									e.setOutput(find(t), v);
									value = ExprTree.toVector(e);
								}	
							
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1236:4: ^( OP_ASSIGN t= OP_WILDCARD e= expr )
					{
					match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3438); 
					match(input, Token.DOWN, null); 
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_assignment3442); 
					pushFollow(FOLLOW_expr_in_assignment3446);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								wildcardError(t, "assignment");
							
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1239:4: ^(t= OP_ASSIGN s= sizedstar f= expr )
					{
					t=(CommonTree)match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3457); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_sizedstar_in_assignment3461);
					s=sizedstar();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_assignment3465);
					f=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.createStore(find(t), s.first, s.second, f);
							
					}
					break;

			}

					code_block_stack.peek().stmtLocation = find(t);
				
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
	// $ANTLR end "assignment"



	// $ANTLR start "bitrange"
	// ghidra/sleigh/grammar/SleighCompiler.g:1244:1: bitrange returns [ExprTree value] : ^(t= OP_BITRANGE ss= specific_symbol[\"bit range\"] a= integer b= integer ) ;
	public final ExprTree bitrange() throws RecognitionException {
		ExprTree value = null;


		CommonTree t=null;
		SpecificSymbol ss =null;
		RadixBigInteger a =null;
		RadixBigInteger b =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1245:2: ( ^(t= OP_BITRANGE ss= specific_symbol[\"bit range\"] a= integer b= integer ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1245:4: ^(t= OP_BITRANGE ss= specific_symbol[\"bit range\"] a= integer b= integer )
			{
			t=(CommonTree)match(input,OP_BITRANGE,FOLLOW_OP_BITRANGE_in_bitrange3486); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_specific_symbol_in_bitrange3490);
			ss=specific_symbol("bit range");
			state._fsp--;

			pushFollow(FOLLOW_integer_in_bitrange3495);
			a=integer();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_bitrange3499);
			b=integer();
			state._fsp--;

			match(input, Token.UP, null); 

			 value = pcode.createBitRange(find(t), ss, toUInt(a), toUInt(b)); 
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
	// ghidra/sleigh/grammar/SleighCompiler.g:1248:1: sizedstar returns [Pair<StarQuality, ExprTree> value] : ( ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer e= expr ) | ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] e= expr ) | ^(t= OP_DEREFERENCE i= integer e= expr ) | ^(t= OP_DEREFERENCE e= expr ) );
	public final Pair<StarQuality, ExprTree> sizedstar() throws RecognitionException {
		Pair<StarQuality, ExprTree> value = null;


		CommonTree t=null;
		SpaceSymbol s =null;
		RadixBigInteger i =null;
		ExprTree e =null;


				StarQuality q = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1255:2: ( ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer e= expr ) | ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] e= expr ) | ^(t= OP_DEREFERENCE i= integer e= expr ) | ^(t= OP_DEREFERENCE e= expr ) )
			int alt57=4;
			alt57 = dfa57.predict(input);
			switch (alt57) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1255:4: ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer e= expr )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstar3532); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_space_symbol_in_sizedstar3536);
					s=space_symbol("sized star operator");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_sizedstar3541);
					i=integer();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_sizedstar3545);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(toUInt(i));
								q.setId(new ConstTpl(s.getSpace()));
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1260:4: ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] e= expr )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstar3556); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_space_symbol_in_sizedstar3560);
					s=space_symbol("sized star operator");
					state._fsp--;

					pushFollow(FOLLOW_expr_in_sizedstar3565);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(0);
								q.setId(new ConstTpl(s.getSpace()));
							
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1265:4: ^(t= OP_DEREFERENCE i= integer e= expr )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstar3576); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_sizedstar3580);
					i=integer();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_sizedstar3584);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(toUInt(i));
								q.setId(new ConstTpl(pcode.getDefaultSpace()));
							
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1270:4: ^(t= OP_DEREFERENCE e= expr )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstar3595); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_sizedstar3599);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(0);
								q.setId(new ConstTpl(pcode.getDefaultSpace()));
							
					}
					break;

			}

					value = new Pair<StarQuality, ExprTree>(q, e);
				
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



	// $ANTLR start "sizedstarv"
	// ghidra/sleigh/grammar/SleighCompiler.g:1277:1: sizedstarv returns [Pair<StarQuality, VarnodeTpl> value] : ( ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE i= integer ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE ss= specific_symbol[\"varnode reference\"] ) );
	public final Pair<StarQuality, VarnodeTpl> sizedstarv() throws RecognitionException {
		Pair<StarQuality, VarnodeTpl> value = null;


		CommonTree t=null;
		SpaceSymbol s =null;
		RadixBigInteger i =null;
		SpecificSymbol ss =null;


				StarQuality q = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1284:2: ( ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE i= integer ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE ss= specific_symbol[\"varnode reference\"] ) )
			int alt58=4;
			alt58 = dfa58.predict(input);
			switch (alt58) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1284:4: ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer ss= specific_symbol[\"varnode reference\"] )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstarv3632); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_space_symbol_in_sizedstarv3636);
					s=space_symbol("sized star operator");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_sizedstarv3641);
					i=integer();
					state._fsp--;

					pushFollow(FOLLOW_specific_symbol_in_sizedstarv3645);
					ss=specific_symbol("varnode reference");
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(toUInt(i));
								q.setId(new ConstTpl(s.getSpace()));
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1289:4: ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] ss= specific_symbol[\"varnode reference\"] )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstarv3657); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_space_symbol_in_sizedstarv3661);
					s=space_symbol("sized star operator");
					state._fsp--;

					pushFollow(FOLLOW_specific_symbol_in_sizedstarv3666);
					ss=specific_symbol("varnode reference");
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(0);
								q.setId(new ConstTpl(s.getSpace()));
							
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1294:4: ^(t= OP_DEREFERENCE i= integer ss= specific_symbol[\"varnode reference\"] )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstarv3678); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_sizedstarv3682);
					i=integer();
					state._fsp--;

					pushFollow(FOLLOW_specific_symbol_in_sizedstarv3686);
					ss=specific_symbol("varnode reference");
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(toUInt(i));
								q.setId(new ConstTpl(pcode.getDefaultSpace()));
							
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1299:4: ^(t= OP_DEREFERENCE ss= specific_symbol[\"varnode reference\"] )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstarv3698); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_specific_symbol_in_sizedstarv3702);
					ss=specific_symbol("varnode reference");
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(0);
								q.setId(new ConstTpl(pcode.getDefaultSpace()));
							
					}
					break;

			}

					value = new Pair<StarQuality, VarnodeTpl>(q, ss.getVarnode());
				
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
	// $ANTLR end "sizedstarv"



	// $ANTLR start "funcall"
	// ghidra/sleigh/grammar/SleighCompiler.g:1306:1: funcall returns [VectorSTL<OpTpl> value] : e= expr_apply ;
	public final VectorSTL<OpTpl> funcall() throws RecognitionException {
		VectorSTL<OpTpl> value = null;


		Object e =null;


				Return_stack.peek().noReturn = true;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1310:2: (e= expr_apply )
			// ghidra/sleigh/grammar/SleighCompiler.g:1310:4: e= expr_apply
			{
			pushFollow(FOLLOW_expr_apply_in_funcall3729);
			e=expr_apply();
			state._fsp--;


						if (e instanceof VectorSTL<?>)
							value = (VectorSTL<OpTpl>) e;
						else {
							Location loc = null;
							if (e instanceof ExprTree) {
								loc = ((ExprTree)e).location;
							}
							reportError(loc,"Functional operator requires a return value");
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
	// $ANTLR end "funcall"



	// $ANTLR start "build_stmt"
	// ghidra/sleigh/grammar/SleighCompiler.g:1323:1: build_stmt returns [VectorSTL<OpTpl> ops] : ^(t= OP_BUILD s= operand_symbol[\"build statement\"] ) ;
	public final VectorSTL<OpTpl> build_stmt() throws RecognitionException {
		VectorSTL<OpTpl> ops = null;


		CommonTree t=null;
		OperandSymbol s =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1327:2: ( ^(t= OP_BUILD s= operand_symbol[\"build statement\"] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1327:4: ^(t= OP_BUILD s= operand_symbol[\"build statement\"] )
			{
			t=(CommonTree)match(input,OP_BUILD,FOLLOW_OP_BUILD_in_build_stmt3755); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_operand_symbol_in_build_stmt3759);
			s=operand_symbol("build statement");
			state._fsp--;

			match(input, Token.UP, null); 


						ops = pcode.createOpConst(find(t), OpCode.CPUI_MULTIEQUAL, s.getIndex());
					
			}


					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return ops;
	}
	// $ANTLR end "build_stmt"



	// $ANTLR start "crossbuild_stmt"
	// ghidra/sleigh/grammar/SleighCompiler.g:1332:1: crossbuild_stmt returns [VectorSTL<OpTpl> ops] : ^(t= OP_CROSSBUILD v= varnode s= section_symbol[\"crossbuild statement\"] ) ;
	public final VectorSTL<OpTpl> crossbuild_stmt() throws RecognitionException {
		VectorSTL<OpTpl> ops = null;


		CommonTree t=null;
		VarnodeTpl v =null;
		SectionSymbol s =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1336:2: ( ^(t= OP_CROSSBUILD v= varnode s= section_symbol[\"crossbuild statement\"] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1336:4: ^(t= OP_CROSSBUILD v= varnode s= section_symbol[\"crossbuild statement\"] )
			{
			t=(CommonTree)match(input,OP_CROSSBUILD,FOLLOW_OP_CROSSBUILD_in_crossbuild_stmt3787); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_varnode_in_crossbuild_stmt3791);
			v=varnode();
			state._fsp--;

			pushFollow(FOLLOW_section_symbol_in_crossbuild_stmt3795);
			s=section_symbol("crossbuild statement");
			state._fsp--;

			match(input, Token.UP, null); 


						ops = pcode.createCrossBuild(find(t), v, s);
					
			}


					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return ops;
	}
	// $ANTLR end "crossbuild_stmt"



	// $ANTLR start "goto_stmt"
	// ghidra/sleigh/grammar/SleighCompiler.g:1341:1: goto_stmt returns [VectorSTL<OpTpl> ops] : ^(t= OP_GOTO j= jumpdest[\"goto destination\"] ) ;
	public final VectorSTL<OpTpl> goto_stmt() throws RecognitionException {
		Jump_stack.push(new Jump_scope());

		VectorSTL<OpTpl> ops = null;


		CommonTree t=null;
		ExprTree j =null;


				Jump_stack.peek().indirect = false;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1349:2: ( ^(t= OP_GOTO j= jumpdest[\"goto destination\"] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1349:4: ^(t= OP_GOTO j= jumpdest[\"goto destination\"] )
			{
			t=(CommonTree)match(input,OP_GOTO,FOLLOW_OP_GOTO_in_goto_stmt3835); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_jumpdest_in_goto_stmt3839);
			j=jumpdest("goto destination");
			state._fsp--;

			match(input, Token.UP, null); 


						ops = pcode.createOpNoOut(find(t), Jump_stack.peek().indirect ? OpCode.CPUI_BRANCHIND : OpCode.CPUI_BRANCH, j);
					
			}


					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			Jump_stack.pop();

		}
		return ops;
	}
	// $ANTLR end "goto_stmt"



	// $ANTLR start "jump_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:1354:1: jump_symbol[String purpose] returns [VarnodeTpl value] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final VarnodeTpl jump_symbol(String purpose) throws RecognitionException {
		VarnodeTpl value = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1355:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt59=2;
			int LA59_0 = input.LA(1);
			if ( (LA59_0==OP_IDENTIFIER) ) {
				alt59=1;
			}
			else if ( (LA59_0==OP_WILDCARD) ) {
				alt59=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 59, 0, input);
				throw nvae;
			}

			switch (alt59) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1355:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_jump_symbol3860); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = pcode.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "start, end, or operand", purpose);
								} else if (sym.getType() == symbol_type.start_symbol ||
										sym.getType() == symbol_type.end_symbol ||
										sym.getType() == symbol_type.next2_symbol ||
										sym.getType() == symbol_type.flowdest_symbol ||
										sym.getType() == symbol_type.flowref_symbol) {
									SpecificSymbol ss = (SpecificSymbol) sym;
									value = new VarnodeTpl(find(s), new ConstTpl(ConstTpl.const_type.j_curspace),
										ss.getVarnode().getOffset(),
										new ConstTpl(ConstTpl.const_type.j_curspace_size));
								} else if(sym.getType() == symbol_type.operand_symbol) {
									OperandSymbol os = (OperandSymbol) sym;
									value = os.getVarnode();
									os.setCodeAddress();
								} else {
									wrongSymbolTypeError(sym, find(s), "start, end, or operand", purpose);
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1376:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_jump_symbol3874); 

								wildcardError(t, purpose);
								value = null;
							
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
	// $ANTLR end "jump_symbol"



	// $ANTLR start "jumpdest"
	// ghidra/sleigh/grammar/SleighCompiler.g:1382:1: jumpdest[String purpose] returns [ExprTree value] : ( ^(t= OP_JUMPDEST_SYMBOL ss= jump_symbol[purpose] ) | ^(t= OP_JUMPDEST_DYNAMIC e= expr ) | ^(t= OP_JUMPDEST_ABSOLUTE i= integer ) | ^(t= OP_JUMPDEST_RELATIVE i= integer s= space_symbol[purpose] ) | ^(t= OP_JUMPDEST_LABEL l= label ) );
	public final ExprTree jumpdest(String purpose) throws RecognitionException {
		ExprTree value = null;


		CommonTree t=null;
		VarnodeTpl ss =null;
		ExprTree e =null;
		RadixBigInteger i =null;
		SpaceSymbol s =null;
		Pair<Location,LabelSymbol> l =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1383:2: ( ^(t= OP_JUMPDEST_SYMBOL ss= jump_symbol[purpose] ) | ^(t= OP_JUMPDEST_DYNAMIC e= expr ) | ^(t= OP_JUMPDEST_ABSOLUTE i= integer ) | ^(t= OP_JUMPDEST_RELATIVE i= integer s= space_symbol[purpose] ) | ^(t= OP_JUMPDEST_LABEL l= label ) )
			int alt60=5;
			switch ( input.LA(1) ) {
			case OP_JUMPDEST_SYMBOL:
				{
				alt60=1;
				}
				break;
			case OP_JUMPDEST_DYNAMIC:
				{
				alt60=2;
				}
				break;
			case OP_JUMPDEST_ABSOLUTE:
				{
				alt60=3;
				}
				break;
			case OP_JUMPDEST_RELATIVE:
				{
				alt60=4;
				}
				break;
			case OP_JUMPDEST_LABEL:
				{
				alt60=5;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 60, 0, input);
				throw nvae;
			}
			switch (alt60) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1383:4: ^(t= OP_JUMPDEST_SYMBOL ss= jump_symbol[purpose] )
					{
					t=(CommonTree)match(input,OP_JUMPDEST_SYMBOL,FOLLOW_OP_JUMPDEST_SYMBOL_in_jumpdest3895); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_jump_symbol_in_jumpdest3899);
					ss=jump_symbol(purpose);
					state._fsp--;

					match(input, Token.UP, null); 


								value = new ExprTree(find(t), ss);
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1386:4: ^(t= OP_JUMPDEST_DYNAMIC e= expr )
					{
					t=(CommonTree)match(input,OP_JUMPDEST_DYNAMIC,FOLLOW_OP_JUMPDEST_DYNAMIC_in_jumpdest3911); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_jumpdest3915);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								value = e;
								if(Jump_stack.isEmpty()) {
									invalidDynamicTargetError(find(t), purpose);
								} else {
									Jump_stack.peek().indirect = true;
								}
							
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1394:4: ^(t= OP_JUMPDEST_ABSOLUTE i= integer )
					{
					t=(CommonTree)match(input,OP_JUMPDEST_ABSOLUTE,FOLLOW_OP_JUMPDEST_ABSOLUTE_in_jumpdest3926); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_jumpdest3930);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 


								value = new ExprTree(find(t), new VarnodeTpl(find(t), new ConstTpl(ConstTpl.const_type.j_curspace),
									new ConstTpl(ConstTpl.const_type.real, toULong(i)),
									new ConstTpl(ConstTpl.const_type.j_curspace_size)));
							
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1399:4: ^(t= OP_JUMPDEST_RELATIVE i= integer s= space_symbol[purpose] )
					{
					t=(CommonTree)match(input,OP_JUMPDEST_RELATIVE,FOLLOW_OP_JUMPDEST_RELATIVE_in_jumpdest3941); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_jumpdest3945);
					i=integer();
					state._fsp--;

					pushFollow(FOLLOW_space_symbol_in_jumpdest3949);
					s=space_symbol(purpose);
					state._fsp--;

					match(input, Token.UP, null); 


								AddrSpace spc = s.getSpace();
								value = new ExprTree(find(t), new VarnodeTpl(find(t), new ConstTpl(spc),
									new ConstTpl(ConstTpl.const_type.real, toSLong(i)),
									new ConstTpl(ConstTpl.const_type.real, spc.getAddrSize())));
							
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1405:4: ^(t= OP_JUMPDEST_LABEL l= label )
					{
					t=(CommonTree)match(input,OP_JUMPDEST_LABEL,FOLLOW_OP_JUMPDEST_LABEL_in_jumpdest3961); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_label_in_jumpdest3965);
					l=label();
					state._fsp--;

					match(input, Token.UP, null); 


								value = new ExprTree(find(t), new VarnodeTpl(find(t), new ConstTpl(pcode.getConstantSpace()),
									new ConstTpl(ConstTpl.const_type.j_relative, l.second.getIndex()),
									new ConstTpl(ConstTpl.const_type.real, 4)));
								l.second.incrementRefCount();
							
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
	// ghidra/sleigh/grammar/SleighCompiler.g:1413:1: cond_stmt returns [VectorSTL<OpTpl> ops] : ^(t= OP_IF e= expr ^( OP_GOTO j= jumpdest[\"goto destination\"] ) ) ;
	public final VectorSTL<OpTpl> cond_stmt() throws RecognitionException {
		VectorSTL<OpTpl> ops = null;


		CommonTree t=null;
		ExprTree e =null;
		ExprTree j =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1417:2: ( ^(t= OP_IF e= expr ^( OP_GOTO j= jumpdest[\"goto destination\"] ) ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1417:4: ^(t= OP_IF e= expr ^( OP_GOTO j= jumpdest[\"goto destination\"] ) )
			{
			t=(CommonTree)match(input,OP_IF,FOLLOW_OP_IF_in_cond_stmt3992); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_expr_in_cond_stmt3996);
			e=expr();
			state._fsp--;

			match(input,OP_GOTO,FOLLOW_OP_GOTO_in_cond_stmt3999); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_jumpdest_in_cond_stmt4003);
			j=jumpdest("goto destination");
			state._fsp--;

			match(input, Token.UP, null); 

			match(input, Token.UP, null); 


						ops = pcode.createOpNoOut(find(t), OpCode.CPUI_CBRANCH, j, e);
					
			}


					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return ops;
	}
	// $ANTLR end "cond_stmt"



	// $ANTLR start "call_stmt"
	// ghidra/sleigh/grammar/SleighCompiler.g:1422:1: call_stmt returns [VectorSTL<OpTpl> ops] : ^(t= OP_CALL j= jumpdest[\"call destination\"] ) ;
	public final VectorSTL<OpTpl> call_stmt() throws RecognitionException {
		Jump_stack.push(new Jump_scope());

		VectorSTL<OpTpl> ops = null;


		CommonTree t=null;
		ExprTree j =null;


				Jump_stack.peek().indirect = false;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1430:2: ( ^(t= OP_CALL j= jumpdest[\"call destination\"] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1430:4: ^(t= OP_CALL j= jumpdest[\"call destination\"] )
			{
			t=(CommonTree)match(input,OP_CALL,FOLLOW_OP_CALL_in_call_stmt4044); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_jumpdest_in_call_stmt4048);
			j=jumpdest("call destination");
			state._fsp--;

			match(input, Token.UP, null); 


						ops = pcode.createOpNoOut(find(t), Jump_stack.peek().indirect ? OpCode.CPUI_CALLIND : OpCode.CPUI_CALL, j);
					
			}


					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			Jump_stack.pop();

		}
		return ops;
	}
	// $ANTLR end "call_stmt"



	// $ANTLR start "return_stmt"
	// ghidra/sleigh/grammar/SleighCompiler.g:1435:1: return_stmt returns [VectorSTL<OpTpl> ops] : ^(t= OP_RETURN e= expr ) ;
	public final VectorSTL<OpTpl> return_stmt() throws RecognitionException {
		VectorSTL<OpTpl> ops = null;


		CommonTree t=null;
		ExprTree e =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1439:2: ( ^(t= OP_RETURN e= expr ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1439:4: ^(t= OP_RETURN e= expr )
			{
			t=(CommonTree)match(input,OP_RETURN,FOLLOW_OP_RETURN_in_return_stmt4076); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_expr_in_return_stmt4080);
			e=expr();
			state._fsp--;

			match(input, Token.UP, null); 


						ops = pcode.createOpNoOut(find(t), OpCode.CPUI_RETURN, e);
					
			}


					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return ops;
	}
	// $ANTLR end "return_stmt"



	// $ANTLR start "export"
	// ghidra/sleigh/grammar/SleighCompiler.g:1444:1: export[ConstructTpl rtl] returns [ConstructTpl value] : ( ^(t= OP_EXPORT q= sizedstarv ) | ^(t= OP_EXPORT v= varnode ) );
	public final ConstructTpl export(ConstructTpl rtl) throws RecognitionException {
		ConstructTpl value = null;


		CommonTree t=null;
		Pair<StarQuality, VarnodeTpl> q =null;
		VarnodeTpl v =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1445:2: ( ^(t= OP_EXPORT q= sizedstarv ) | ^(t= OP_EXPORT v= varnode ) )
			int alt61=2;
			int LA61_0 = input.LA(1);
			if ( (LA61_0==OP_EXPORT) ) {
				int LA61_1 = input.LA(2);
				if ( (LA61_1==DOWN) ) {
					int LA61_2 = input.LA(3);
					if ( (LA61_2==OP_DEREFERENCE) ) {
						alt61=1;
					}
					else if ( (LA61_2==OP_ADDRESS_OF||LA61_2==OP_IDENTIFIER||LA61_2==OP_TRUNCATION_SIZE||LA61_2==OP_WILDCARD) ) {
						alt61=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 61, 2, input);
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
							new NoViableAltException("", 61, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 61, 0, input);
				throw nvae;
			}

			switch (alt61) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1445:4: ^(t= OP_EXPORT q= sizedstarv )
					{
					t=(CommonTree)match(input,OP_EXPORT,FOLLOW_OP_EXPORT_in_export4102); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_sizedstarv_in_export4106);
					q=sizedstarv();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.setResultStarVarnode(rtl, q.first, q.second);
								code_block_stack.peek().stmtLocation = find(t);
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1449:4: ^(t= OP_EXPORT v= varnode )
					{
					t=(CommonTree)match(input,OP_EXPORT,FOLLOW_OP_EXPORT_in_export4117); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_varnode_in_export4121);
					v=varnode();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.setResultVarnode(rtl, v);
								code_block_stack.peek().stmtLocation = find(t);
							
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
	// $ANTLR end "export"



	// $ANTLR start "expr"
	// ghidra/sleigh/grammar/SleighCompiler.g:1455:1: expr returns [ExprTree value] : ( ^(t= OP_BOOL_OR l= expr r= expr ) | ^(t= OP_BOOL_XOR l= expr r= expr ) | ^(t= OP_BOOL_AND l= expr r= expr ) | ^(t= OP_OR l= expr r= expr ) | ^(t= OP_XOR l= expr r= expr ) | ^(t= OP_AND l= expr r= expr ) | ^(t= OP_EQUAL l= expr r= expr ) | ^(t= OP_NOTEQUAL l= expr r= expr ) | ^(t= OP_FEQUAL l= expr r= expr ) | ^(t= OP_FNOTEQUAL l= expr r= expr ) | ^(t= OP_LESS l= expr r= expr ) | ^(t= OP_GREATEQUAL l= expr r= expr ) | ^(t= OP_LESSEQUAL l= expr r= expr ) | ^(t= OP_GREAT l= expr r= expr ) | ^(t= OP_SLESS l= expr r= expr ) | ^(t= OP_SGREATEQUAL l= expr r= expr ) | ^(t= OP_SLESSEQUAL l= expr r= expr ) | ^(t= OP_SGREAT l= expr r= expr ) | ^(t= OP_FLESS l= expr r= expr ) | ^(t= OP_FGREATEQUAL l= expr r= expr ) | ^(t= OP_FLESSEQUAL l= expr r= expr ) | ^(t= OP_FGREAT l= expr r= expr ) | ^(t= OP_LEFT l= expr r= expr ) | ^(t= OP_RIGHT l= expr r= expr ) | ^(t= OP_SRIGHT l= expr r= expr ) | ^(t= OP_ADD l= expr r= expr ) | ^(t= OP_SUB l= expr r= expr ) | ^(t= OP_FADD l= expr r= expr ) | ^(t= OP_FSUB l= expr r= expr ) | ^(t= OP_MULT l= expr r= expr ) | ^(t= OP_DIV l= expr r= expr ) | ^(t= OP_REM l= expr r= expr ) | ^(t= OP_SDIV l= expr r= expr ) | ^(t= OP_SREM l= expr r= expr ) | ^(t= OP_FMULT l= expr r= expr ) | ^(t= OP_FDIV l= expr r= expr ) | ^(t= OP_NOT l= expr ) | ^(t= OP_INVERT l= expr ) | ^(t= OP_NEGATE l= expr ) | ^(t= OP_FNEGATE l= expr ) |s= sizedstar |a= expr_apply |v= varnode_or_bitsym[\"expression\"] |b= bitrange |i= integer | ^( OP_PARENTHESIZED l= expr ) | ^(t= OP_BITRANGE2 ss= specific_symbol[\"expression\"] i= integer ) );
	public final ExprTree expr() throws RecognitionException {
		ExprTree value = null;


		CommonTree t=null;
		ExprTree l =null;
		ExprTree r =null;
		Pair<StarQuality, ExprTree> s =null;
		Object a =null;
		ExprTree v =null;
		ExprTree b =null;
		RadixBigInteger i =null;
		SpecificSymbol ss =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1456:2: ( ^(t= OP_BOOL_OR l= expr r= expr ) | ^(t= OP_BOOL_XOR l= expr r= expr ) | ^(t= OP_BOOL_AND l= expr r= expr ) | ^(t= OP_OR l= expr r= expr ) | ^(t= OP_XOR l= expr r= expr ) | ^(t= OP_AND l= expr r= expr ) | ^(t= OP_EQUAL l= expr r= expr ) | ^(t= OP_NOTEQUAL l= expr r= expr ) | ^(t= OP_FEQUAL l= expr r= expr ) | ^(t= OP_FNOTEQUAL l= expr r= expr ) | ^(t= OP_LESS l= expr r= expr ) | ^(t= OP_GREATEQUAL l= expr r= expr ) | ^(t= OP_LESSEQUAL l= expr r= expr ) | ^(t= OP_GREAT l= expr r= expr ) | ^(t= OP_SLESS l= expr r= expr ) | ^(t= OP_SGREATEQUAL l= expr r= expr ) | ^(t= OP_SLESSEQUAL l= expr r= expr ) | ^(t= OP_SGREAT l= expr r= expr ) | ^(t= OP_FLESS l= expr r= expr ) | ^(t= OP_FGREATEQUAL l= expr r= expr ) | ^(t= OP_FLESSEQUAL l= expr r= expr ) | ^(t= OP_FGREAT l= expr r= expr ) | ^(t= OP_LEFT l= expr r= expr ) | ^(t= OP_RIGHT l= expr r= expr ) | ^(t= OP_SRIGHT l= expr r= expr ) | ^(t= OP_ADD l= expr r= expr ) | ^(t= OP_SUB l= expr r= expr ) | ^(t= OP_FADD l= expr r= expr ) | ^(t= OP_FSUB l= expr r= expr ) | ^(t= OP_MULT l= expr r= expr ) | ^(t= OP_DIV l= expr r= expr ) | ^(t= OP_REM l= expr r= expr ) | ^(t= OP_SDIV l= expr r= expr ) | ^(t= OP_SREM l= expr r= expr ) | ^(t= OP_FMULT l= expr r= expr ) | ^(t= OP_FDIV l= expr r= expr ) | ^(t= OP_NOT l= expr ) | ^(t= OP_INVERT l= expr ) | ^(t= OP_NEGATE l= expr ) | ^(t= OP_FNEGATE l= expr ) |s= sizedstar |a= expr_apply |v= varnode_or_bitsym[\"expression\"] |b= bitrange |i= integer | ^( OP_PARENTHESIZED l= expr ) | ^(t= OP_BITRANGE2 ss= specific_symbol[\"expression\"] i= integer ) )
			int alt62=47;
			switch ( input.LA(1) ) {
			case OP_BOOL_OR:
				{
				alt62=1;
				}
				break;
			case OP_BOOL_XOR:
				{
				alt62=2;
				}
				break;
			case OP_BOOL_AND:
				{
				alt62=3;
				}
				break;
			case OP_OR:
				{
				alt62=4;
				}
				break;
			case OP_XOR:
				{
				alt62=5;
				}
				break;
			case OP_AND:
				{
				alt62=6;
				}
				break;
			case OP_EQUAL:
				{
				alt62=7;
				}
				break;
			case OP_NOTEQUAL:
				{
				alt62=8;
				}
				break;
			case OP_FEQUAL:
				{
				alt62=9;
				}
				break;
			case OP_FNOTEQUAL:
				{
				alt62=10;
				}
				break;
			case OP_LESS:
				{
				alt62=11;
				}
				break;
			case OP_GREATEQUAL:
				{
				alt62=12;
				}
				break;
			case OP_LESSEQUAL:
				{
				alt62=13;
				}
				break;
			case OP_GREAT:
				{
				alt62=14;
				}
				break;
			case OP_SLESS:
				{
				alt62=15;
				}
				break;
			case OP_SGREATEQUAL:
				{
				alt62=16;
				}
				break;
			case OP_SLESSEQUAL:
				{
				alt62=17;
				}
				break;
			case OP_SGREAT:
				{
				alt62=18;
				}
				break;
			case OP_FLESS:
				{
				alt62=19;
				}
				break;
			case OP_FGREATEQUAL:
				{
				alt62=20;
				}
				break;
			case OP_FLESSEQUAL:
				{
				alt62=21;
				}
				break;
			case OP_FGREAT:
				{
				alt62=22;
				}
				break;
			case OP_LEFT:
				{
				alt62=23;
				}
				break;
			case OP_RIGHT:
				{
				alt62=24;
				}
				break;
			case OP_SRIGHT:
				{
				alt62=25;
				}
				break;
			case OP_ADD:
				{
				alt62=26;
				}
				break;
			case OP_SUB:
				{
				alt62=27;
				}
				break;
			case OP_FADD:
				{
				alt62=28;
				}
				break;
			case OP_FSUB:
				{
				alt62=29;
				}
				break;
			case OP_MULT:
				{
				alt62=30;
				}
				break;
			case OP_DIV:
				{
				alt62=31;
				}
				break;
			case OP_REM:
				{
				alt62=32;
				}
				break;
			case OP_SDIV:
				{
				alt62=33;
				}
				break;
			case OP_SREM:
				{
				alt62=34;
				}
				break;
			case OP_FMULT:
				{
				alt62=35;
				}
				break;
			case OP_FDIV:
				{
				alt62=36;
				}
				break;
			case OP_NOT:
				{
				alt62=37;
				}
				break;
			case OP_INVERT:
				{
				alt62=38;
				}
				break;
			case OP_NEGATE:
				{
				alt62=39;
				}
				break;
			case OP_FNEGATE:
				{
				alt62=40;
				}
				break;
			case OP_DEREFERENCE:
				{
				alt62=41;
				}
				break;
			case OP_APPLY:
				{
				alt62=42;
				}
				break;
			case OP_ADDRESS_OF:
			case OP_IDENTIFIER:
			case OP_TRUNCATION_SIZE:
			case OP_WILDCARD:
				{
				alt62=43;
				}
				break;
			case OP_BITRANGE:
				{
				alt62=44;
				}
				break;
			case OP_BIN_CONSTANT:
			case OP_DEC_CONSTANT:
			case OP_HEX_CONSTANT:
				{
				alt62=45;
				}
				break;
			case OP_PARENTHESIZED:
				{
				alt62=46;
				}
				break;
			case OP_BITRANGE2:
				{
				alt62=47;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 62, 0, input);
				throw nvae;
			}
			switch (alt62) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1456:4: ^(t= OP_BOOL_OR l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_BOOL_OR,FOLLOW_OP_BOOL_OR_in_expr4142); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4146);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4150);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_BOOL_OR,l,r); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1457:4: ^(t= OP_BOOL_XOR l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_BOOL_XOR,FOLLOW_OP_BOOL_XOR_in_expr4161); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4165);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4169);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_BOOL_XOR,l,r); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1458:4: ^(t= OP_BOOL_AND l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_BOOL_AND,FOLLOW_OP_BOOL_AND_in_expr4180); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4184);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4188);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_BOOL_AND,l,r); 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1460:4: ^(t= OP_OR l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_OR,FOLLOW_OP_OR_in_expr4200); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4204);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4208);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_OR,l,r); 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1461:4: ^(t= OP_XOR l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_XOR,FOLLOW_OP_XOR_in_expr4219); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4223);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4227);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_XOR,l,r); 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1462:4: ^(t= OP_AND l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_AND,FOLLOW_OP_AND_in_expr4238); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4242);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4246);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_AND,l,r); 
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1464:4: ^(t= OP_EQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_EQUAL,FOLLOW_OP_EQUAL_in_expr4258); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4262);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4266);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_EQUAL,l,r); 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1465:4: ^(t= OP_NOTEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_NOTEQUAL,FOLLOW_OP_NOTEQUAL_in_expr4277); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4281);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4285);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_NOTEQUAL,l,r); 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1466:4: ^(t= OP_FEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FEQUAL,FOLLOW_OP_FEQUAL_in_expr4296); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4300);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4304);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_EQUAL,l,r); 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1467:4: ^(t= OP_FNOTEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FNOTEQUAL,FOLLOW_OP_FNOTEQUAL_in_expr4315); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4319);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4323);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_NOTEQUAL,l,r); 
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1469:4: ^(t= OP_LESS l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_LESS,FOLLOW_OP_LESS_in_expr4335); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4339);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4343);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_LESS,l,r); 
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1470:4: ^(t= OP_GREATEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_GREATEQUAL,FOLLOW_OP_GREATEQUAL_in_expr4354); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4358);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4362);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_LESSEQUAL,r,l); 
					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1471:4: ^(t= OP_LESSEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_LESSEQUAL,FOLLOW_OP_LESSEQUAL_in_expr4373); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4377);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4381);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_LESSEQUAL,l,r); 
					}
					break;
				case 14 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1472:4: ^(t= OP_GREAT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_GREAT,FOLLOW_OP_GREAT_in_expr4392); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4396);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4400);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_LESS,r,l); 
					}
					break;
				case 15 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1473:4: ^(t= OP_SLESS l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SLESS,FOLLOW_OP_SLESS_in_expr4411); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4415);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4419);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SLESS,l,r); 
					}
					break;
				case 16 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1474:4: ^(t= OP_SGREATEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SGREATEQUAL,FOLLOW_OP_SGREATEQUAL_in_expr4430); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4434);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4438);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SLESSEQUAL,r,l); 
					}
					break;
				case 17 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1475:4: ^(t= OP_SLESSEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SLESSEQUAL,FOLLOW_OP_SLESSEQUAL_in_expr4449); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4453);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4457);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SLESSEQUAL,l,r); 
					}
					break;
				case 18 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1476:4: ^(t= OP_SGREAT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SGREAT,FOLLOW_OP_SGREAT_in_expr4468); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4472);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4476);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SLESS,r,l); 
					}
					break;
				case 19 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1477:4: ^(t= OP_FLESS l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FLESS,FOLLOW_OP_FLESS_in_expr4487); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4491);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4495);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_LESS,l,r); 
					}
					break;
				case 20 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1478:4: ^(t= OP_FGREATEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FGREATEQUAL,FOLLOW_OP_FGREATEQUAL_in_expr4506); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4510);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4514);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_LESSEQUAL,r,l); 
					}
					break;
				case 21 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1479:4: ^(t= OP_FLESSEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FLESSEQUAL,FOLLOW_OP_FLESSEQUAL_in_expr4525); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4529);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4533);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_LESSEQUAL,l,r); 
					}
					break;
				case 22 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1480:4: ^(t= OP_FGREAT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FGREAT,FOLLOW_OP_FGREAT_in_expr4544); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4548);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4552);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_LESS,r,l); 
					}
					break;
				case 23 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1482:4: ^(t= OP_LEFT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_LEFT,FOLLOW_OP_LEFT_in_expr4564); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4568);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4572);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_LEFT,l,r); 
					}
					break;
				case 24 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1483:4: ^(t= OP_RIGHT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_RIGHT,FOLLOW_OP_RIGHT_in_expr4583); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4587);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4591);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_RIGHT,l,r); 
					}
					break;
				case 25 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1484:4: ^(t= OP_SRIGHT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SRIGHT,FOLLOW_OP_SRIGHT_in_expr4602); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4606);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4610);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SRIGHT,l,r); 
					}
					break;
				case 26 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1486:4: ^(t= OP_ADD l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_ADD,FOLLOW_OP_ADD_in_expr4622); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4626);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4630);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_ADD,l,r); 
					}
					break;
				case 27 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1487:4: ^(t= OP_SUB l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SUB,FOLLOW_OP_SUB_in_expr4641); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4645);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4649);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SUB,l,r); 
					}
					break;
				case 28 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1488:4: ^(t= OP_FADD l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FADD,FOLLOW_OP_FADD_in_expr4660); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4664);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4668);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_ADD,l,r); 
					}
					break;
				case 29 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1489:4: ^(t= OP_FSUB l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FSUB,FOLLOW_OP_FSUB_in_expr4679); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4683);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4687);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_SUB,l,r); 
					}
					break;
				case 30 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1491:4: ^(t= OP_MULT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_MULT,FOLLOW_OP_MULT_in_expr4699); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4703);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4707);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_MULT,l,r); 
					}
					break;
				case 31 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1492:4: ^(t= OP_DIV l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_DIV,FOLLOW_OP_DIV_in_expr4718); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4722);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4726);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_DIV,l,r); 
					}
					break;
				case 32 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1493:4: ^(t= OP_REM l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_REM,FOLLOW_OP_REM_in_expr4737); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4741);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4745);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_REM,l,r); 
					}
					break;
				case 33 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1494:4: ^(t= OP_SDIV l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SDIV,FOLLOW_OP_SDIV_in_expr4756); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4760);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4764);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SDIV,l,r); 
					}
					break;
				case 34 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1495:4: ^(t= OP_SREM l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SREM,FOLLOW_OP_SREM_in_expr4775); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4779);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4783);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SREM,l,r); 
					}
					break;
				case 35 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1496:4: ^(t= OP_FMULT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FMULT,FOLLOW_OP_FMULT_in_expr4794); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4798);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4802);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_MULT,l,r); 
					}
					break;
				case 36 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1497:4: ^(t= OP_FDIV l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FDIV,FOLLOW_OP_FDIV_in_expr4813); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4817);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4821);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_DIV,l,r); 
					}
					break;
				case 37 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1499:4: ^(t= OP_NOT l= expr )
					{
					t=(CommonTree)match(input,OP_NOT,FOLLOW_OP_NOT_in_expr4833); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4837);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_BOOL_NEGATE,l); 
					}
					break;
				case 38 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1500:4: ^(t= OP_INVERT l= expr )
					{
					t=(CommonTree)match(input,OP_INVERT,FOLLOW_OP_INVERT_in_expr4848); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4852);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_NEGATE,l); 
					}
					break;
				case 39 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1501:4: ^(t= OP_NEGATE l= expr )
					{
					t=(CommonTree)match(input,OP_NEGATE,FOLLOW_OP_NEGATE_in_expr4863); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4867);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_2COMP,l); 
					}
					break;
				case 40 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1502:4: ^(t= OP_FNEGATE l= expr )
					{
					t=(CommonTree)match(input,OP_FNEGATE,FOLLOW_OP_FNEGATE_in_expr4878); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4882);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_NEG,l); 
					}
					break;
				case 41 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1503:4: s= sizedstar
					{
					pushFollow(FOLLOW_sizedstar_in_expr4892);
					s=sizedstar();
					state._fsp--;

					 value = pcode.createLoad(s.first.location, s.first, s.second); 
					}
					break;
				case 42 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1505:4: a= expr_apply
					{
					pushFollow(FOLLOW_expr_apply_in_expr4902);
					a=expr_apply();
					state._fsp--;

					 value = (ExprTree) a; 
					}
					break;
				case 43 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1506:4: v= varnode_or_bitsym[\"expression\"]
					{
					pushFollow(FOLLOW_varnode_or_bitsym_in_expr4911);
					v=varnode_or_bitsym("expression");
					state._fsp--;

					 value = v; 
					}
					break;
				case 44 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1507:4: b= bitrange
					{
					pushFollow(FOLLOW_bitrange_in_expr4921);
					b=bitrange();
					state._fsp--;

					 value = b; 
					}
					break;
				case 45 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1508:4: i= integer
					{
					pushFollow(FOLLOW_integer_in_expr4930);
					i=integer();
					state._fsp--;

					 value = new ExprTree(i.location, new VarnodeTpl(i.location, new ConstTpl(pcode.getConstantSpace()),
									new ConstTpl(ConstTpl.const_type.real, toLong(i)),
									new ConstTpl(ConstTpl.const_type.real, 0)));
							
					}
					break;
				case 46 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1512:4: ^( OP_PARENTHESIZED l= expr )
					{
					match(input,OP_PARENTHESIZED,FOLLOW_OP_PARENTHESIZED_in_expr4938); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4942);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l; 
					}
					break;
				case 47 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1514:4: ^(t= OP_BITRANGE2 ss= specific_symbol[\"expression\"] i= integer )
					{
					t=(CommonTree)match(input,OP_BITRANGE2,FOLLOW_OP_BITRANGE2_in_expr4954); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_specific_symbol_in_expr4958);
					ss=specific_symbol("expression");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_expr4963);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.createBitRange(find(t), ss, 0, toUInt(i) * 8);
							
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



	// $ANTLR start "varnode_or_bitsym"
	// ghidra/sleigh/grammar/SleighCompiler.g:1519:1: varnode_or_bitsym[String purpose] returns [ExprTree value] : ( ^(t= OP_IDENTIFIER s= . ) |v= varnode_adorned |t= OP_WILDCARD );
	public final ExprTree varnode_or_bitsym(String purpose) throws RecognitionException {
		ExprTree value = null;


		CommonTree t=null;
		CommonTree s=null;
		VarnodeTpl v =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1520:2: ( ^(t= OP_IDENTIFIER s= . ) |v= varnode_adorned |t= OP_WILDCARD )
			int alt63=3;
			switch ( input.LA(1) ) {
			case OP_IDENTIFIER:
				{
				alt63=1;
				}
				break;
			case OP_ADDRESS_OF:
			case OP_TRUNCATION_SIZE:
				{
				alt63=2;
				}
				break;
			case OP_WILDCARD:
				{
				alt63=3;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 63, 0, input);
				throw nvae;
			}
			switch (alt63) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1520:4: ^(t= OP_IDENTIFIER s= . )
					{
					t=(CommonTree)match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_varnode_or_bitsym4985); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


					            SleighSymbol sym = pcode.findSymbol(s.getText());
					            if (sym == null) {
					                unknownSymbolError(s.getText(), find(s), "varnode or bitrange symbol", purpose);
					            } else if (sym instanceof BitrangeSymbol) {
					                BitrangeSymbol bitSym = (BitrangeSymbol)sym;
					                value = pcode.createBitRange(find(t), bitSym.getParentSymbol(),
					                                              bitSym.getBitOffset(),
					                                              bitSym.numBits());
					            } else if (sym instanceof SpecificSymbol) {
					                VarnodeTpl vTemp = ((SpecificSymbol)sym).getVarnode();
					                value = new ExprTree(vTemp.location, vTemp);
					            } else {
					                undeclaredSymbolError(sym, find(s), purpose);
					            }
					        
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1536:4: v= varnode_adorned
					{
					pushFollow(FOLLOW_varnode_adorned_in_varnode_or_bitsym4999);
					v=varnode_adorned();
					state._fsp--;

					 value = new ExprTree(v.location,v); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1537:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_varnode_or_bitsym5008); 

								wildcardError(t, purpose);
								value = null;
							
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
	// $ANTLR end "varnode_or_bitsym"



	// $ANTLR start "expr_apply"
	// ghidra/sleigh/grammar/SleighCompiler.g:1543:1: expr_apply returns [Object value] : ( ^(x= OP_APPLY ^(t= OP_IDENTIFIER s= . ) o= expr_operands ) | ^(x= OP_APPLY t= OP_WILDCARD o= expr_operands ) );
	public final Object expr_apply() throws RecognitionException {
		Object value = null;


		CommonTree x=null;
		CommonTree t=null;
		CommonTree s=null;
		VectorSTL<ExprTree> o =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1547:2: ( ^(x= OP_APPLY ^(t= OP_IDENTIFIER s= . ) o= expr_operands ) | ^(x= OP_APPLY t= OP_WILDCARD o= expr_operands ) )
			int alt64=2;
			int LA64_0 = input.LA(1);
			if ( (LA64_0==OP_APPLY) ) {
				int LA64_1 = input.LA(2);
				if ( (LA64_1==DOWN) ) {
					int LA64_2 = input.LA(3);
					if ( (LA64_2==OP_IDENTIFIER) ) {
						alt64=1;
					}
					else if ( (LA64_2==OP_WILDCARD) ) {
						alt64=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 64, 2, input);
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
							new NoViableAltException("", 64, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 64, 0, input);
				throw nvae;
			}

			switch (alt64) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1547:4: ^(x= OP_APPLY ^(t= OP_IDENTIFIER s= . ) o= expr_operands )
					{
					x=(CommonTree)match(input,OP_APPLY,FOLLOW_OP_APPLY_in_expr_apply5034); 
					match(input, Token.DOWN, null); 
					t=(CommonTree)match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_expr_apply5039); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					pushFollow(FOLLOW_expr_operands_in_expr_apply5048);
					o=expr_operands();
					state._fsp--;

					match(input, Token.UP, null); 


								Object internalFunction = pcode.findInternalFunction(find(s), s.getText(), o);
								if (internalFunction == null) {
									SleighSymbol sym = pcode.findSymbol(s.getText());
									if (sym == null) {
										unknownSymbolError(s.getText(), find(s), "macro, userop, or specific symbol", "macro, user operation, or subpiece application");
									} else if(sym.getType() == symbol_type.userop_symbol) {
										if(Return_stack.peek().noReturn) {
											value = pcode.createUserOpNoOut(find(s), (UserOpSymbol) sym, o);
										} else {
											value = pcode.createUserOp((UserOpSymbol) sym, o);
										}
									} else if(sym.getType() == symbol_type.macro_symbol) {
										if(Return_stack.peek().noReturn) {
											value = pcode.createMacroUse(find(x), (MacroSymbol) sym, o);
										} else {
											pcode.reportError(find(t), "macro invocation not allowed as expression");
										}
									} else if(sym.getType() == symbol_type.start_symbol
										|| sym.getType() == symbol_type.end_symbol
										|| sym.getType() == symbol_type.next2_symbol
										|| sym.getType() == symbol_type.flowdest_symbol
										|| sym.getType() == symbol_type.flowref_symbol
										|| sym.getType() == symbol_type.operand_symbol
										|| sym.getType() == symbol_type.epsilon_symbol
										|| sym.getType() == symbol_type.varnode_symbol) {
										if (o.size() != 1) {
											pcode.reportError(find(t), "subpiece operation requires a single operand");
										} else {
											value = pcode.createOp(find(s), OpCode.CPUI_SUBPIECE,new ExprTree(find(s), ((SpecificSymbol)sym).getVarnode()), o.get(0));
										}
									} else {
										wrongSymbolTypeError(sym, find(s), "macro, userop, or specific symbol", "macro, user operation, or subpiece application");
									}
								} else {
									value = internalFunction;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1585:4: ^(x= OP_APPLY t= OP_WILDCARD o= expr_operands )
					{
					x=(CommonTree)match(input,OP_APPLY,FOLLOW_OP_APPLY_in_expr_apply5059); 
					match(input, Token.DOWN, null); 
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_expr_apply5063); 
					pushFollow(FOLLOW_expr_operands_in_expr_apply5067);
					o=expr_operands();
					state._fsp--;

					match(input, Token.UP, null); 


								wildcardError(t, "function application");
							
					}
					break;

			}

					code_block_stack.peek().stmtLocation = find(x);
				
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
	// ghidra/sleigh/grammar/SleighCompiler.g:1590:1: expr_operands returns [VectorSTL<ExprTree> value] : (e= expr )* ;
	public final VectorSTL<ExprTree> expr_operands() throws RecognitionException {
		Return_stack.push(new Return_scope());

		VectorSTL<ExprTree> value = null;


		ExprTree e =null;


				value = new VectorSTL<ExprTree>();
				Return_stack.peek().noReturn = false;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1596:2: ( (e= expr )* )
			// ghidra/sleigh/grammar/SleighCompiler.g:1596:4: (e= expr )*
			{
			// ghidra/sleigh/grammar/SleighCompiler.g:1596:4: (e= expr )*
			loop65:
			while (true) {
				int alt65=2;
				int LA65_0 = input.LA(1);
				if ( ((LA65_0 >= OP_ADD && LA65_0 <= OP_ADDRESS_OF)||(LA65_0 >= OP_AND && LA65_0 <= OP_APPLY)||(LA65_0 >= OP_BIN_CONSTANT && LA65_0 <= OP_BITRANGE2)||(LA65_0 >= OP_BOOL_AND && LA65_0 <= OP_BOOL_XOR)||LA65_0==OP_DEC_CONSTANT||LA65_0==OP_DEREFERENCE||LA65_0==OP_DIV||LA65_0==OP_EQUAL||(LA65_0 >= OP_FADD && LA65_0 <= OP_FGREATEQUAL)||(LA65_0 >= OP_FLESS && LA65_0 <= OP_FSUB)||(LA65_0 >= OP_GREAT && LA65_0 <= OP_GREATEQUAL)||(LA65_0 >= OP_HEX_CONSTANT && LA65_0 <= OP_IDENTIFIER)||LA65_0==OP_INVERT||(LA65_0 >= OP_LEFT && LA65_0 <= OP_LESSEQUAL)||LA65_0==OP_MULT||LA65_0==OP_NEGATE||(LA65_0 >= OP_NOT && LA65_0 <= OP_NOTEQUAL)||(LA65_0 >= OP_OR && LA65_0 <= OP_PARENTHESIZED)||LA65_0==OP_REM||(LA65_0 >= OP_RIGHT && LA65_0 <= OP_SDIV)||(LA65_0 >= OP_SGREAT && LA65_0 <= OP_SGREATEQUAL)||(LA65_0 >= OP_SLESS && LA65_0 <= OP_SLESSEQUAL)||(LA65_0 >= OP_SREM && LA65_0 <= OP_SRIGHT)||LA65_0==OP_SUB||LA65_0==OP_TRUNCATION_SIZE||LA65_0==OP_WILDCARD||LA65_0==OP_XOR) ) {
					alt65=1;
				}

				switch (alt65) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1596:5: e= expr
					{
					pushFollow(FOLLOW_expr_in_expr_operands5100);
					e=expr();
					state._fsp--;

					 value.push_back(e); 
					}
					break;

				default :
					break loop65;
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
			Return_stack.pop();

		}
		return value;
	}
	// $ANTLR end "expr_operands"



	// $ANTLR start "varnode_adorned"
	// ghidra/sleigh/grammar/SleighCompiler.g:1599:1: varnode_adorned returns [VarnodeTpl value] : ( ^(t= OP_TRUNCATION_SIZE n= integer m= integer ) | ^( OP_ADDRESS_OF ^( OP_SIZING_SIZE i= integer ) v= varnode ) | ^( OP_ADDRESS_OF v= varnode ) );
	public final VarnodeTpl varnode_adorned() throws RecognitionException {
		VarnodeTpl value = null;


		CommonTree t=null;
		RadixBigInteger n =null;
		RadixBigInteger m =null;
		RadixBigInteger i =null;
		VarnodeTpl v =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1600:2: ( ^(t= OP_TRUNCATION_SIZE n= integer m= integer ) | ^( OP_ADDRESS_OF ^( OP_SIZING_SIZE i= integer ) v= varnode ) | ^( OP_ADDRESS_OF v= varnode ) )
			int alt66=3;
			int LA66_0 = input.LA(1);
			if ( (LA66_0==OP_TRUNCATION_SIZE) ) {
				alt66=1;
			}
			else if ( (LA66_0==OP_ADDRESS_OF) ) {
				int LA66_2 = input.LA(2);
				if ( (LA66_2==DOWN) ) {
					int LA66_3 = input.LA(3);
					if ( (LA66_3==OP_SIZING_SIZE) ) {
						alt66=2;
					}
					else if ( (LA66_3==OP_ADDRESS_OF||LA66_3==OP_IDENTIFIER||LA66_3==OP_TRUNCATION_SIZE||LA66_3==OP_WILDCARD) ) {
						alt66=3;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 66, 3, input);
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
							new NoViableAltException("", 66, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 66, 0, input);
				throw nvae;
			}

			switch (alt66) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1600:4: ^(t= OP_TRUNCATION_SIZE n= integer m= integer )
					{
					t=(CommonTree)match(input,OP_TRUNCATION_SIZE,FOLLOW_OP_TRUNCATION_SIZE_in_varnode_adorned5122); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_varnode_adorned5126);
					n=integer();
					state._fsp--;

					pushFollow(FOLLOW_integer_in_varnode_adorned5130);
					m=integer();
					state._fsp--;

					match(input, Token.UP, null); 


								if (toULong(m) > 8) {
									reportError(find(t), "Constant varnode size must not exceed 8 (" +
									n + ":" + m + ")");
								}
								value = new VarnodeTpl(find(t), new ConstTpl(pcode.getConstantSpace()),
									new ConstTpl(ConstTpl.const_type.real, toLong(n)),
									new ConstTpl(ConstTpl.const_type.real, toULong(m)));
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1609:4: ^( OP_ADDRESS_OF ^( OP_SIZING_SIZE i= integer ) v= varnode )
					{
					match(input,OP_ADDRESS_OF,FOLLOW_OP_ADDRESS_OF_in_varnode_adorned5139); 
					match(input, Token.DOWN, null); 
					match(input,OP_SIZING_SIZE,FOLLOW_OP_SIZING_SIZE_in_varnode_adorned5142); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_varnode_adorned5146);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					pushFollow(FOLLOW_varnode_in_varnode_adorned5151);
					v=varnode();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.addressOf(v, toUInt(i)); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1610:4: ^( OP_ADDRESS_OF v= varnode )
					{
					match(input,OP_ADDRESS_OF,FOLLOW_OP_ADDRESS_OF_in_varnode_adorned5160); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_varnode_in_varnode_adorned5164);
					v=varnode();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.addressOf(v, 0); 
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
	// $ANTLR end "varnode_adorned"



	// $ANTLR start "varnode"
	// ghidra/sleigh/grammar/SleighCompiler.g:1613:1: varnode returns [VarnodeTpl value] : (ss= specific_symbol[\"varnode reference\"] |v= varnode_adorned );
	public final VarnodeTpl varnode() throws RecognitionException {
		VarnodeTpl value = null;


		SpecificSymbol ss =null;
		VarnodeTpl v =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1614:2: (ss= specific_symbol[\"varnode reference\"] |v= varnode_adorned )
			int alt67=2;
			int LA67_0 = input.LA(1);
			if ( (LA67_0==OP_IDENTIFIER||LA67_0==OP_WILDCARD) ) {
				alt67=1;
			}
			else if ( (LA67_0==OP_ADDRESS_OF||LA67_0==OP_TRUNCATION_SIZE) ) {
				alt67=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 67, 0, input);
				throw nvae;
			}

			switch (alt67) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1614:4: ss= specific_symbol[\"varnode reference\"]
					{
					pushFollow(FOLLOW_specific_symbol_in_varnode5184);
					ss=specific_symbol("varnode reference");
					state._fsp--;

					 value = ss.getVarnode(); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1615:4: v= varnode_adorned
					{
					pushFollow(FOLLOW_varnode_adorned_in_varnode5194);
					v=varnode_adorned();
					state._fsp--;

					 value = v; 
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



	// $ANTLR start "qstring"
	// ghidra/sleigh/grammar/SleighCompiler.g:1618:1: qstring returns [String value] : ^( OP_QSTRING s= . ) ;
	public final String qstring() throws RecognitionException {
		String value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1619:2: ( ^( OP_QSTRING s= . ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1619:4: ^( OP_QSTRING s= . )
			{
			match(input,OP_QSTRING,FOLLOW_OP_QSTRING_in_qstring5212); 
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
	// $ANTLR end "qstring"


	public static class identifier_return extends TreeRuleReturnScope {
		public String value;
		public Tree tree;
	};


	// $ANTLR start "identifier"
	// ghidra/sleigh/grammar/SleighCompiler.g:1622:1: identifier returns [String value, Tree tree] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final SleighCompiler.identifier_return identifier() throws RecognitionException {
		SleighCompiler.identifier_return retval = new SleighCompiler.identifier_return();
		retval.start = input.LT(1);

		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1623:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt68=2;
			int LA68_0 = input.LA(1);
			if ( (LA68_0==OP_IDENTIFIER) ) {
				alt68=1;
			}
			else if ( (LA68_0==OP_WILDCARD) ) {
				alt68=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 68, 0, input);
				throw nvae;
			}

			switch (alt68) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1623:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_identifier5235); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 retval.value = s.getText(); retval.tree = s; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1624:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_identifier5249); 
					 retval.value = null; retval.tree = s; 
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
		return retval;
	}
	// $ANTLR end "identifier"



	// $ANTLR start "integer"
	// ghidra/sleigh/grammar/SleighCompiler.g:1627:1: integer returns [RadixBigInteger value] : ( ^( OP_HEX_CONSTANT s= . ) | ^( OP_DEC_CONSTANT s= . ) | ^( OP_BIN_CONSTANT s= . ) );
	public final RadixBigInteger integer() throws RecognitionException {
		RadixBigInteger value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1628:2: ( ^( OP_HEX_CONSTANT s= . ) | ^( OP_DEC_CONSTANT s= . ) | ^( OP_BIN_CONSTANT s= . ) )
			int alt69=3;
			switch ( input.LA(1) ) {
			case OP_HEX_CONSTANT:
				{
				alt69=1;
				}
				break;
			case OP_DEC_CONSTANT:
				{
				alt69=2;
				}
				break;
			case OP_BIN_CONSTANT:
				{
				alt69=3;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 69, 0, input);
				throw nvae;
			}
			switch (alt69) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1628:4: ^( OP_HEX_CONSTANT s= . )
					{
					match(input,OP_HEX_CONSTANT,FOLLOW_OP_HEX_CONSTANT_in_integer5267); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = new RadixBigInteger(find(s), s.getText().substring(2), 16); check(value); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1629:4: ^( OP_DEC_CONSTANT s= . )
					{
					match(input,OP_DEC_CONSTANT,FOLLOW_OP_DEC_CONSTANT_in_integer5280); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = new RadixBigInteger(find(s), s.getText()); check(value); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1630:4: ^( OP_BIN_CONSTANT s= . )
					{
					match(input,OP_BIN_CONSTANT,FOLLOW_OP_BIN_CONSTANT_in_integer5293); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = new RadixBigInteger(find(s), s.getText().substring(2), 2); check(value); 
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


	protected DFA52 dfa52 = new DFA52(this);
	protected DFA57 dfa57 = new DFA57(this);
	protected DFA58 dfa58 = new DFA58(this);
	static final String DFA52_eotS =
		"\15\uffff";
	static final String DFA52_eofS =
		"\15\uffff";
	static final String DFA52_minS =
		"\1\u009a\1\2\1\u008b\1\2\1\3\1\4\2\uffff\1\2\1\4\3\3";
	static final String DFA52_maxS =
		"\1\u009a\1\2\1\u00cc\1\2\1\u008a\1\u00ee\2\uffff\1\3\1\u00ee\1\u008a\1"+
		"\u00ee\1\3";
	static final String DFA52_acceptS =
		"\6\uffff\1\1\1\2\5\uffff";
	static final String DFA52_specialS =
		"\15\uffff}>";
	static final String[] DFA52_transitionS = {
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

	static final short[] DFA52_eot = DFA.unpackEncodedString(DFA52_eotS);
	static final short[] DFA52_eof = DFA.unpackEncodedString(DFA52_eofS);
	static final char[] DFA52_min = DFA.unpackEncodedStringToUnsignedChars(DFA52_minS);
	static final char[] DFA52_max = DFA.unpackEncodedStringToUnsignedChars(DFA52_maxS);
	static final short[] DFA52_accept = DFA.unpackEncodedString(DFA52_acceptS);
	static final short[] DFA52_special = DFA.unpackEncodedString(DFA52_specialS);
	static final short[][] DFA52_transition;

	static {
		int numStates = DFA52_transitionS.length;
		DFA52_transition = new short[numStates][];
		for (int i=0; i<numStates; i++) {
			DFA52_transition[i] = DFA.unpackEncodedString(DFA52_transitionS[i]);
		}
	}

	protected class DFA52 extends DFA {

		public DFA52(BaseRecognizer recognizer) {
			this.recognizer = recognizer;
			this.decisionNumber = 52;
			this.eot = DFA52_eot;
			this.eof = DFA52_eof;
			this.min = DFA52_min;
			this.max = DFA52_max;
			this.accept = DFA52_accept;
			this.special = DFA52_special;
			this.transition = DFA52_transition;
		}
		@Override
		public String getDescription() {
			return "1131:1: declaration : ( ^( OP_LOCAL n= unbound_identifier[\"sized local declaration\"] i= integer ) | ^( OP_LOCAL n= unbound_identifier[\"local declaration\"] ) );";
		}
	}

	static final String DFA57_eotS =
		"\71\uffff";
	static final String DFA57_eofS =
		"\71\uffff";
	static final String DFA57_minS =
		"\1\157\1\2\1\123\1\2\1\3\3\2\1\uffff\1\4\3\2\1\uffff\3\4\1\2\3\4\3\2\1"+
		"\4\1\3\3\2\1\4\1\3\1\4\1\3\1\4\2\3\1\4\1\3\1\4\1\3\1\4\2\3\1\uffff\4\3"+
		"\1\uffff\10\3";
	static final String DFA57_maxS =
		"\1\157\1\2\1\u00cf\1\2\1\u00cf\3\2\1\uffff\1\u00ee\3\2\1\uffff\3\u00ee"+
		"\1\3\3\u00ee\3\3\1\u00ee\1\u00cf\3\3\1\u00ee\1\u00cf\1\u00ee\1\u00cf\1"+
		"\u00ee\1\u00cf\2\u00ee\1\u00cf\1\u00ee\1\u00cf\1\u00ee\1\u00cf\1\u00ee"+
		"\1\uffff\2\u00ee\1\3\1\u00ee\1\uffff\2\u00ee\6\3";
	static final String DFA57_acceptS =
		"\10\uffff\1\4\4\uffff\1\2\35\uffff\1\3\4\uffff\1\1\10\uffff";
	static final String DFA57_specialS =
		"\71\uffff}>";
	static final String[] DFA57_transitionS = {
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

	static final short[] DFA57_eot = DFA.unpackEncodedString(DFA57_eotS);
	static final short[] DFA57_eof = DFA.unpackEncodedString(DFA57_eofS);
	static final char[] DFA57_min = DFA.unpackEncodedStringToUnsignedChars(DFA57_minS);
	static final char[] DFA57_max = DFA.unpackEncodedStringToUnsignedChars(DFA57_maxS);
	static final short[] DFA57_accept = DFA.unpackEncodedString(DFA57_acceptS);
	static final short[] DFA57_special = DFA.unpackEncodedString(DFA57_specialS);
	static final short[][] DFA57_transition;

	static {
		int numStates = DFA57_transitionS.length;
		DFA57_transition = new short[numStates][];
		for (int i=0; i<numStates; i++) {
			DFA57_transition[i] = DFA.unpackEncodedString(DFA57_transitionS[i]);
		}
	}

	protected class DFA57 extends DFA {

		public DFA57(BaseRecognizer recognizer) {
			this.recognizer = recognizer;
			this.decisionNumber = 57;
			this.eot = DFA57_eot;
			this.eof = DFA57_eof;
			this.min = DFA57_min;
			this.max = DFA57_max;
			this.accept = DFA57_accept;
			this.special = DFA57_special;
			this.transition = DFA57_transition;
		}
		@Override
		public String getDescription() {
			return "1248:1: sizedstar returns [Pair<StarQuality, ExprTree> value] : ( ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer e= expr ) | ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] e= expr ) | ^(t= OP_DEREFERENCE i= integer e= expr ) | ^(t= OP_DEREFERENCE e= expr ) );";
		}
	}

	static final String DFA58_eotS =
		"\17\uffff";
	static final String DFA58_eofS =
		"\17\uffff";
	static final String DFA58_minS =
		"\1\157\1\2\1\133\1\2\1\3\1\uffff\1\4\3\uffff\1\2\1\4\3\3";
	static final String DFA58_maxS =
		"\1\157\1\2\1\u00cc\1\2\1\u00cc\1\uffff\1\u00ee\3\uffff\1\3\1\u00ee\1\u00cc"+
		"\1\u00ee\1\3";
	static final String DFA58_acceptS =
		"\5\uffff\1\3\1\uffff\1\1\1\2\1\4\5\uffff";
	static final String DFA58_specialS =
		"\17\uffff}>";
	static final String[] DFA58_transitionS = {
			"\1\1",
			"\1\2",
			"\1\5\21\uffff\1\5\34\uffff\1\5\1\3\100\uffff\1\4",
			"\1\6",
			"\1\11\127\uffff\1\7\21\uffff\1\7\34\uffff\1\7\1\10\100\uffff\1\10",
			"",
			"\u00eb\12",
			"",
			"",
			"",
			"\1\13\1\14",
			"\u00eb\15",
			"\1\11\127\uffff\1\7\21\uffff\1\7\34\uffff\1\7\1\10\100\uffff\1\10",
			"\1\16\u00eb\15",
			"\1\14"
	};

	static final short[] DFA58_eot = DFA.unpackEncodedString(DFA58_eotS);
	static final short[] DFA58_eof = DFA.unpackEncodedString(DFA58_eofS);
	static final char[] DFA58_min = DFA.unpackEncodedStringToUnsignedChars(DFA58_minS);
	static final char[] DFA58_max = DFA.unpackEncodedStringToUnsignedChars(DFA58_maxS);
	static final short[] DFA58_accept = DFA.unpackEncodedString(DFA58_acceptS);
	static final short[] DFA58_special = DFA.unpackEncodedString(DFA58_specialS);
	static final short[][] DFA58_transition;

	static {
		int numStates = DFA58_transitionS.length;
		DFA58_transition = new short[numStates][];
		for (int i=0; i<numStates; i++) {
			DFA58_transition[i] = DFA.unpackEncodedString(DFA58_transitionS[i]);
		}
	}

	protected class DFA58 extends DFA {

		public DFA58(BaseRecognizer recognizer) {
			this.recognizer = recognizer;
			this.decisionNumber = 58;
			this.eot = DFA58_eot;
			this.eof = DFA58_eof;
			this.min = DFA58_min;
			this.max = DFA58_max;
			this.accept = DFA58_accept;
			this.special = DFA58_special;
			this.transition = DFA58_transition;
		}
		@Override
		public String getDescription() {
			return "1277:1: sizedstarv returns [Pair<StarQuality, VarnodeTpl> value] : ( ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE i= integer ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE ss= specific_symbol[\"varnode reference\"] ) );";
		}
	}

	public static final BitSet FOLLOW_endiandef_in_root80 = new BitSet(new long[]{0x0000000000000002L,0x000000C040200000L,0x0400040028000000L,0x0000000000002718L});
	public static final BitSet FOLLOW_definition_in_root86 = new BitSet(new long[]{0x0000000000000002L,0x000000C040200000L,0x0400040028000000L,0x0000000000002718L});
	public static final BitSet FOLLOW_constructorlike_in_root92 = new BitSet(new long[]{0x0000000000000002L,0x000000C040200000L,0x0400040028000000L,0x0000000000002718L});
	public static final BitSet FOLLOW_OP_ENDIAN_in_endiandef109 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_endian_in_endiandef113 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BIG_in_endian131 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_LITTLE_in_endian141 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_aligndef_in_definition155 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_tokendef_in_definition160 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_contextdef_in_definition165 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_spacedef_in_definition170 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_varnodedef_in_definition175 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_bitrangedef_in_definition180 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pcodeopdef_in_definition185 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_valueattach_in_definition190 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_nameattach_in_definition195 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_varattach_in_definition200 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_ALIGNMENT_in_aligndef215 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_aligndef219 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_TOKEN_in_tokendef245 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_identifier_in_tokendef249 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_tokendef254 = new BitSet(new long[]{0x0000000000000000L,0x4000000000000000L});
	public static final BitSet FOLLOW_fielddefs_in_tokendef258 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_TOKEN_ENDIAN_in_tokendef267 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_identifier_in_tokendef271 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_tokendef276 = new BitSet(new long[]{0x0000000000000000L,0x0000000004000000L,0x0000000002000000L});
	public static final BitSet FOLLOW_endian_in_tokendef280 = new BitSet(new long[]{0x0000000000000000L,0x4000000000000000L});
	public static final BitSet FOLLOW_fielddefs_in_tokendef284 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FIELDDEFS_in_fielddefs297 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_fielddef_in_fielddefs299 = new BitSet(new long[]{0x0000000000000008L,0x2000000000000000L});
	public static final BitSet FOLLOW_OP_FIELDDEF_in_fielddef325 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_fielddef329 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_fielddef334 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_fielddef338 = new BitSet(new long[]{0x0000000000000000L,0x8000000000000000L,0x0000004000000000L});
	public static final BitSet FOLLOW_fieldmods_in_fielddef342 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FIELD_MODS_in_fieldmods357 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_fieldmod_in_fieldmods359 = new BitSet(new long[]{0x0000000000000008L,0x0000080000000000L,0x0020000100000200L});
	public static final BitSet FOLLOW_OP_NO_FIELD_MOD_in_fieldmods366 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_SIGNED_in_fieldmod382 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NOFLOW_in_fieldmod394 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_HEX_in_fieldmod406 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_DEC_in_fieldmod418 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_specific_identifier440 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_specific_identifier454 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_unbound_identifier473 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_unbound_identifier487 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_varnode_symbol506 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_varnode_symbol520 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_value_symbol539 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_value_symbol553 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_operand_symbol572 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_operand_symbol586 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_space_symbol605 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_space_symbol619 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_specific_symbol638 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_specific_symbol652 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_family_symbol671 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_family_symbol685 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_CONTEXT_in_contextdef710 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_symbol_in_contextdef714 = new BitSet(new long[]{0x0000000000000000L,0x4000000000000000L});
	public static final BitSet FOLLOW_fielddefs_in_contextdef719 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SPACE_in_spacedef743 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_spacedef747 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0800000000000000L});
	public static final BitSet FOLLOW_spacemods_in_spacedef754 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SPACEMODS_in_spacemods769 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_spacemod_in_spacemods771 = new BitSet(new long[]{0x0000000000000008L,0x0000400000000000L,0x0040000000000000L,0x0000000000004040L});
	public static final BitSet FOLLOW_typemod_in_spacemod784 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_sizemod_in_spacemod789 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_wordsizemod_in_spacemod794 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_DEFAULT_in_spacemod799 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_TYPE_in_typemod813 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_identifier_in_typemod817 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SIZE_in_sizemod833 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_sizemod837 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_WORDSIZE_in_wordsizemod852 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_wordsizemod856 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_VARNODE_in_varnodedef871 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_space_symbol_in_varnodedef875 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_varnodedef880 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_varnodedef884 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000001000L});
	public static final BitSet FOLLOW_identifierlist_in_varnodedef888 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_LIST_in_identifierlist919 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_identifierlist927 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_identifierlist943 = new BitSet(new long[]{0x0000000000000008L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_OP_STRING_OR_IDENT_LIST_in_stringoridentlist971 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_stringorident_in_stringoridentlist976 = new BitSet(new long[]{0x0000000000000008L,0x0000000000000000L,0x0000080000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_identifier_in_stringorident999 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_qstring_in_stringorident1008 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_BITRANGES_in_bitrangedef1022 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_sbitrange_in_bitrangedef1024 = new BitSet(new long[]{0x0000000000000008L,0x0000000010000000L});
	public static final BitSet FOLLOW_OP_BITRANGE_in_sbitrange1038 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_sbitrange1041 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_symbol_in_sbitrange1050 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_sbitrange1055 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_sbitrange1059 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_PCODEOP_in_pcodeopdef1074 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifierlist_in_pcodeopdef1078 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_VALUES_in_valueattach1099 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_valuelist_in_valueattach1103 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000004000L});
	public static final BitSet FOLLOW_intblist_in_valueattach1108 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_INTBLIST_in_intblist1133 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_intbpart_in_intblist1138 = new BitSet(new long[]{0x0000000000000008L,0x0000200008000000L,0x0000000040000400L,0x0000000000001000L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_intbpart1161 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NEGATE_in_intbpart1169 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_intbpart1173 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_integer_in_intbpart1183 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NAMES_in_nameattach1203 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_valuelist_in_nameattach1207 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x8000000000000000L});
	public static final BitSet FOLLOW_stringoridentlist_in_nameattach1212 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_VARIABLES_in_varattach1233 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_valuelist_in_varattach1237 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000001000L});
	public static final BitSet FOLLOW_varlist_in_varattach1242 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_LIST_in_valuelist1275 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_value_symbol_in_valuelist1280 = new BitSet(new long[]{0x0000000000000008L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_LIST_in_varlist1311 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_symbol_in_varlist1316 = new BitSet(new long[]{0x0000000000000008L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_macrodef_in_constructorlike1334 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_withblock_in_constructorlike1341 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_constructor_in_constructorlike1348 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_MACRO_in_macrodef1373 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_macrodef1377 = new BitSet(new long[]{0x0000000000000000L,0x0010000001000000L});
	public static final BitSet FOLLOW_arguments_in_macrodef1382 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0002000000000000L});
	public static final BitSet FOLLOW_semantic_in_macrodef1388 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ARGUMENTS_in_arguments1420 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_arguments1424 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_EMPTY_LIST_in_arguments1439 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_WITH_in_withblock1451 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_id_or_nil_in_withblock1455 = new BitSet(new long[]{0x0000000000000000L,0x0000000080000000L,0x0000000080000000L});
	public static final BitSet FOLLOW_bitpat_or_nil_in_withblock1459 = new BitSet(new long[]{0x0000000000000000L,0x0000010000000000L,0x0000002000000000L});
	public static final BitSet FOLLOW_contextblock_in_withblock1463 = new BitSet(new long[]{0x0000000000000000L,0x0000040000000000L});
	public static final BitSet FOLLOW_constructorlikelist_in_withblock1469 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_identifier_in_id_or_nil1491 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NIL_in_id_or_nil1498 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_bitpattern_in_bitpat_or_nil1517 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NIL_in_bitpat_or_nil1524 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_CTLIST_in_constructorlikelist1538 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_definition_in_constructorlikelist1542 = new BitSet(new long[]{0x0000000000000008L,0x000000C040200000L,0x0400040028000000L,0x0000000000002718L});
	public static final BitSet FOLLOW_constructorlike_in_constructorlikelist1546 = new BitSet(new long[]{0x0000000000000008L,0x000000C040200000L,0x0400040028000000L,0x0000000000002718L});
	public static final BitSet FOLLOW_OP_CONSTRUCTOR_in_constructor1563 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_ctorstart_in_constructor1567 = new BitSet(new long[]{0x0000000000000000L,0x0000000080000000L});
	public static final BitSet FOLLOW_bitpattern_in_constructor1571 = new BitSet(new long[]{0x0000000000000000L,0x0000010000000000L,0x0000002000000000L});
	public static final BitSet FOLLOW_contextblock_in_constructor1575 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_ctorsemantic_in_constructor1579 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_PCODE_in_ctorsemantic1602 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_semantic_in_ctorsemantic1606 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_PCODE_in_ctorsemantic1616 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_UNIMPL_in_ctorsemantic1618 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BIT_PATTERN_in_bitpattern1637 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_bitpattern1641 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SUBTABLE_in_ctorstart1673 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_ctorstart1677 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_ctorstart1691 = new BitSet(new long[]{0x0000000000000000L,0x0001000000000000L});
	public static final BitSet FOLLOW_display_in_ctorstart1698 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_TABLE_in_ctorstart1710 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_display_in_ctorstart1716 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DISPLAY_in_display1733 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pieces_in_display1737 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_printpiece_in_pieces1751 = new BitSet(new long[]{0x0000000000000002L,0x0000002000000000L,0x4000080000000800L,0x0000000000000800L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_printpiece1772 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_whitespace_in_printpiece1786 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_CONCATENATE_in_printpiece1793 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_string_in_printpiece1800 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_WHITESPACE_in_whitespace1818 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_STRING_in_string1841 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_QSTRING_in_string1854 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_BOOL_OR_in_pequation1885 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1889 = new BitSet(new long[]{0x0000000000000000L,0x004C000300000000L,0x0004010801800980L,0x0000000000001000L});
	public static final BitSet FOLLOW_pequation_in_pequation1893 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SEQUENCE_in_pequation1904 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1908 = new BitSet(new long[]{0x0000000000000000L,0x004C000300000000L,0x0004010801800980L,0x0000000000001000L});
	public static final BitSet FOLLOW_pequation_in_pequation1912 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BOOL_AND_in_pequation1923 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1927 = new BitSet(new long[]{0x0000000000000000L,0x004C000300000000L,0x0004010801800980L,0x0000000000001000L});
	public static final BitSet FOLLOW_pequation_in_pequation1931 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ELLIPSIS_in_pequation1943 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1947 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ELLIPSIS_RIGHT_in_pequation1958 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1962 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_EQUAL_in_pequation1974 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_family_or_operand_symbol_in_pequation1978 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pequation1983 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NOTEQUAL_in_pequation1994 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_family_symbol_in_pequation1998 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pequation2003 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LESS_in_pequation2014 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_family_symbol_in_pequation2018 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pequation2023 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LESSEQUAL_in_pequation2034 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_family_symbol_in_pequation2038 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pequation2043 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GREAT_in_pequation2054 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_family_symbol_in_pequation2058 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pequation2063 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GREATEQUAL_in_pequation2074 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_family_symbol_in_pequation2078 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pequation2083 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_pequation_symbol_in_pequation2094 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_PARENTHESIZED_in_pequation2103 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation2107 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_family_or_operand_symbol2128 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_family_or_operand_symbol2142 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_pequation_symbol2161 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_pequation_symbol2175 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_OR_in_pexpression2195 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2199 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2203 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_XOR_in_pexpression2214 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2218 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2222 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_AND_in_pexpression2233 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2237 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2241 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LEFT_in_pexpression2252 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2256 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2260 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_RIGHT_in_pexpression2271 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2275 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2279 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADD_in_pexpression2290 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2294 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2298 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SUB_in_pexpression2309 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2313 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2317 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_MULT_in_pexpression2328 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2332 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2336 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DIV_in_pexpression2347 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2351 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2355 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NEGATE_in_pexpression2367 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2371 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_INVERT_in_pexpression2382 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2386 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_pattern_symbol_in_pexpression2398 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_pexpression2408 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_PARENTHESIZED_in_pexpression2416 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2420 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_OR_in_pexpression22441 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22445 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22449 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_XOR_in_pexpression22460 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22464 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22468 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_AND_in_pexpression22479 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22483 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22487 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LEFT_in_pexpression22498 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22502 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22506 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_RIGHT_in_pexpression22517 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22521 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22525 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADD_in_pexpression22536 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22540 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22544 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SUB_in_pexpression22555 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22559 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22563 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_MULT_in_pexpression22574 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22578 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22582 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DIV_in_pexpression22593 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22597 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000009001L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22601 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NEGATE_in_pexpression22613 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22617 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_INVERT_in_pexpression22628 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22632 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_pattern_symbol2_in_pexpression22644 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_pexpression22654 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_PARENTHESIZED_in_pexpression22662 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22666 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_pattern_symbol2686 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_pattern_symbol2700 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_pattern_symbol22719 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_pattern_symbol22733 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_CONTEXT_BLOCK_in_contextblock2751 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_cstatements_in_contextblock2755 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NO_CONTEXT_BLOCK_in_contextblock2763 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_cstatement_in_cstatements2785 = new BitSet(new long[]{0x0000000000000002L,0x0000000002800000L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_cstatement2800 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_cstatement2803 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_cstatement2812 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_APPLY_in_cstatement2821 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_cstatement2824 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_cstatement2832 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_cstatement2840 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_SEMANTIC_in_semantic2884 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_code_block_in_semantic2888 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_statements_in_code_block2939 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NOP_in_code_block2944 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_statement_in_statements2955 = new BitSet(new long[]{0x0000000000000002L,0x0080021802800000L,0x0001200004202040L});
	public static final BitSet FOLLOW_assignment_in_statement2987 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_declaration_in_statement2999 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_funcall_in_statement3011 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_build_stmt_in_statement3028 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_crossbuild_stmt_in_statement3042 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_goto_stmt_in_statement3051 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_cond_stmt_in_statement3066 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_call_stmt_in_statement3081 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_return_stmt_in_statement3096 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_label_in_statement3109 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_export_in_statement3118 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_section_label_in_statement3128 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_LOCAL_in_declaration3142 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_declaration3146 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_declaration3151 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LOCAL_in_declaration3160 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_declaration3164 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LABEL_in_label3184 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_label3188 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_label3204 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SECTION_LABEL_in_section_label3224 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_section_label3228 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_section_label3244 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_section_symbol3265 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_section_symbol3279 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3305 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_BITRANGE_in_assignment3308 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_symbol_in_assignment3312 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_assignment3317 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_assignment3321 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_expr_in_assignment3326 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3337 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_DECLARATIVE_SIZE_in_assignment3340 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_assignment3344 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_assignment3349 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_expr_in_assignment3354 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LOCAL_in_assignment3363 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3367 = new BitSet(new long[]{0x0000000000000000L,0x0000100000000000L});
	public static final BitSet FOLLOW_OP_DECLARATIVE_SIZE_in_assignment3370 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_assignment3374 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_assignment3379 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_expr_in_assignment3384 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LOCAL_in_assignment3393 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3397 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_unbound_identifier_in_assignment3401 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_assignment3406 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3417 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_assignment3420 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_assignment3429 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3438 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_assignment3442 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_assignment3446 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3457 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_sizedstar_in_assignment3461 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_assignment3465 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BITRANGE_in_bitrange3486 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_symbol_in_bitrange3490 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_bitrange3495 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_bitrange3499 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstar3532 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_space_symbol_in_sizedstar3536 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_sizedstar3541 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_sizedstar3545 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstar3556 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_space_symbol_in_sizedstar3560 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_sizedstar3565 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstar3576 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_sizedstar3580 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_sizedstar3584 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstar3595 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_sizedstar3599 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstarv3632 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_space_symbol_in_sizedstarv3636 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_sizedstarv3641 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_specific_symbol_in_sizedstarv3645 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstarv3657 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_space_symbol_in_sizedstarv3661 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_specific_symbol_in_sizedstarv3666 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstarv3678 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_sizedstarv3682 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_specific_symbol_in_sizedstarv3686 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstarv3698 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_symbol_in_sizedstarv3702 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_expr_apply_in_funcall3729 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_BUILD_in_build_stmt3755 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_operand_symbol_in_build_stmt3759 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_CROSSBUILD_in_crossbuild_stmt3787 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_in_crossbuild_stmt3791 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_section_symbol_in_crossbuild_stmt3795 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GOTO_in_goto_stmt3835 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_jumpdest_in_goto_stmt3839 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_jump_symbol3860 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_jump_symbol3874 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_JUMPDEST_SYMBOL_in_jumpdest3895 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_jump_symbol_in_jumpdest3899 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_DYNAMIC_in_jumpdest3911 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_jumpdest3915 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_ABSOLUTE_in_jumpdest3926 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_jumpdest3930 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_RELATIVE_in_jumpdest3941 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_jumpdest3945 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000001000L});
	public static final BitSet FOLLOW_space_symbol_in_jumpdest3949 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_LABEL_in_jumpdest3961 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_label_in_jumpdest3965 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IF_in_cond_stmt3992 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_cond_stmt3996 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000040L});
	public static final BitSet FOLLOW_OP_GOTO_in_cond_stmt3999 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_jumpdest_in_cond_stmt4003 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_CALL_in_call_stmt4044 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_jumpdest_in_call_stmt4048 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_RETURN_in_return_stmt4076 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_return_stmt4080 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_EXPORT_in_export4102 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_sizedstarv_in_export4106 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_EXPORT_in_export4117 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_in_export4121 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BOOL_OR_in_expr4142 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4146 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4150 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BOOL_XOR_in_expr4161 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4165 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4169 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BOOL_AND_in_expr4180 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4184 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4188 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_OR_in_expr4200 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4204 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4208 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_XOR_in_expr4219 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4223 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4227 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_AND_in_expr4238 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4242 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4246 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_EQUAL_in_expr4258 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4262 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4266 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NOTEQUAL_in_expr4277 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4281 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4285 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FEQUAL_in_expr4296 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4300 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4304 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FNOTEQUAL_in_expr4315 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4319 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4323 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LESS_in_expr4335 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4339 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4343 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GREATEQUAL_in_expr4354 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4358 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4362 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LESSEQUAL_in_expr4373 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4377 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4381 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GREAT_in_expr4392 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4396 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4400 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SLESS_in_expr4411 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4415 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4419 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SGREATEQUAL_in_expr4430 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4434 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4438 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SLESSEQUAL_in_expr4449 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4453 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4457 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SGREAT_in_expr4468 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4472 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4476 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FLESS_in_expr4487 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4491 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4495 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FGREATEQUAL_in_expr4506 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4510 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4514 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FLESSEQUAL_in_expr4525 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4529 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4533 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FGREAT_in_expr4544 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4548 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4552 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LEFT_in_expr4564 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4568 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4572 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_RIGHT_in_expr4583 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4587 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4591 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SRIGHT_in_expr4602 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4606 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4610 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADD_in_expr4622 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4626 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4630 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SUB_in_expr4641 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4645 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4649 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FADD_in_expr4660 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4664 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4668 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FSUB_in_expr4679 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4683 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4687 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_MULT_in_expr4699 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4703 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4707 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DIV_in_expr4718 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4722 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4726 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_REM_in_expr4737 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4741 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4745 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SDIV_in_expr4756 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4760 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4764 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SREM_in_expr4775 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4779 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4783 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FMULT_in_expr4794 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4798 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4802 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FDIV_in_expr4813 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4817 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_in_expr4821 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NOT_in_expr4833 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4837 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_INVERT_in_expr4848 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4852 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NEGATE_in_expr4863 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4867 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FNEGATE_in_expr4878 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4882 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_sizedstar_in_expr4892 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_apply_in_expr4902 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_varnode_or_bitsym_in_expr4911 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_bitrange_in_expr4921 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_expr4930 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_PARENTHESIZED_in_expr4938 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4942 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BITRANGE2_in_expr4954 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_symbol_in_expr4958 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_expr4963 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_varnode_or_bitsym4985 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_adorned_in_varnode_or_bitsym4999 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_varnode_or_bitsym5008 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_APPLY_in_expr_apply5034 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_expr_apply5039 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_operands_in_expr_apply5048 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_APPLY_in_expr_apply5059 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_expr_apply5063 = new BitSet(new long[]{0x0000000000000008L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_expr_operands_in_expr_apply5067 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_expr_in_expr_operands5100 = new BitSet(new long[]{0x0000000000000002L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000009021L});
	public static final BitSet FOLLOW_OP_TRUNCATION_SIZE_in_varnode_adorned5122 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_varnode_adorned5126 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_varnode_adorned5130 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADDRESS_OF_in_varnode_adorned5139 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_SIZING_SIZE_in_varnode_adorned5142 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_varnode_adorned5146 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_varnode_in_varnode_adorned5151 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADDRESS_OF_in_varnode_adorned5160 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_in_varnode_adorned5164 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_specific_symbol_in_varnode5184 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_varnode_adorned_in_varnode5194 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_QSTRING_in_qstring5212 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_identifier5235 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_identifier5249 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_HEX_CONSTANT_in_integer5267 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_DEC_CONSTANT_in_integer5280 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_BIN_CONSTANT_in_integer5293 = new BitSet(new long[]{0x0000000000000004L});
}
