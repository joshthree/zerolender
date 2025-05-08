package zero_knowledge_proofs.CryptoData;

import java.math.BigInteger;
import java.util.Base64;

public class BigIntData extends CryptoData {
	/**
	 * 
	 */
	private static final long serialVersionUID = 5968736215439976858L;
	BigInteger data;
	
	public BigIntData(BigInteger data)
	{
		if(data == null) throw new NullPointerException();
		this.data = data;
	}
	@Override
	public BigInteger getBigInt() {
		return data;
	}

	@Override
	public CryptoData[] getCryptoDataArray() {
		return null;
	}
	@Override
	public int size() {
		return 1;
	}

	@Override
	public String toString()
	{
		if(data == null) return null;
		return data.toString();
	}
	@Override
	public String toString64()
	{
		return Base64.getEncoder().encodeToString(data.toByteArray());
	}
	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		return data.toByteArray();
	}
}
