package zero_knowledge_proofs.CryptoData;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.StringTokenizer;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.InvalidStringFormatException;



public abstract class CryptoData implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 8646352085520649067L;
	public BigInteger getBigInt() {
		return null;
	}
	abstract public CryptoData[] getCryptoDataArray();
	abstract public int size();
	
	public CryptoData getEmbeddedCryptoData(int[] index, int pos)
	{
		throw new ArrayIndexOutOfBoundsException("Attempting to access index " + index[pos] + " of a non-array object.");
	}
	
	public int getFirstNullIndex()
	{
		throw new ArrayIndexOutOfBoundsException("Not an Array");
	}
	
	public static CryptoData generateData(String str) throws InvalidStringFormatException
	{
		System.out.println(str);
		if(str.charAt(0) != '[' || str.charAt(str.length()-1) != ']') throw new InvalidStringFormatException();
		
		String args = str.substring(1, str.length() - 1);
		
		if(args.charAt(0) != '[')
		{
			if(args.indexOf('[') != -1) throw new InvalidStringFormatException();
			StringTokenizer tok = new StringTokenizer(args,",");
			BigIntData[] array = new BigIntData[tok.countTokens()];
			for(int i = 0; tok.hasMoreTokens(); i++)
			{
				String blah = tok.nextToken();
				if(blah.equals("")) blah = "0";
				array[i] = new BigIntData(new BigInteger(blah));
			}
			return new CryptoDataArray(array);
		}
		else
		{
			char c;
			int start = 0;
			int inBracket = 0;
			ArrayList<String> list = new ArrayList<String>();
			for(int i = 0; i < args.length(); i++)
			{
				c = args.charAt(i);
				if(c == '[') inBracket++;
				if(c == ']') inBracket--;
				if(inBracket < 0) throw new InvalidStringFormatException();
				if(inBracket == 0 && c == ',')
				{
					if(start == i) throw new InvalidStringFormatException();
					list.add(args.substring(start, i));
					start = i+1;
					if(args.charAt(start) != '[') throw new InvalidStringFormatException();
				}
			}
			if(start != str.length())
				list.add(args.substring(start));
			
			CryptoData[] data = new CryptoData[list.size()];
			for(int i = 0; i < data.length; i++)
			{
				data[i] = generateData(list.get(i));
			}
			return new CryptoDataArray(data);
		}
	}
	public void addFillDataHole(CryptoData d)
	{
		throw new ArrayIndexOutOfBoundsException("Not an array.");
	}
	public ECCurve getECCurveData() {
		return null;
	}
	public ECPoint getECPointData(ECCurve c) {
		return null;
	}

	public abstract String toString64();
	public boolean hasNull() {
		return false;
	}
	abstract public byte[] getBytes();
}
