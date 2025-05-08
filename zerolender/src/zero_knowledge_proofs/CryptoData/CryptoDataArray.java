package zero_knowledge_proofs.CryptoData;

import java.math.BigInteger;
import java.util.LinkedList;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public class CryptoDataArray extends CryptoData {

	/**
	 * 
	 */
	private static final long serialVersionUID = -664917513934888003L;
	private CryptoData[] data;
	private LinkedList<Integer> nulls = null;
	
	@Override
	public int getFirstNullIndex()
	{
		if(nulls == null) return -1;
		return nulls.get(0);
	}
	
	public CryptoDataArray(CryptoData[] data)
	{
		super();
		this.data = new CryptoData[data.length];
		for(int i = 0; i < data.length; i++)
		{
			this.data[i] = data[i];
			if(data[i] == null || data[i].hasNull())
			{
				if(nulls == null)
				{
					nulls = new LinkedList<Integer>();
				}
				nulls.add(i);
			}
		}
	}
	public CryptoDataArray(BigInteger[] data)
	{
		super();
		this.data = new CryptoData[data.length];
		for(int i = 0; i < data.length; i++)
		{
			if(data[i] == null) {
				this.data[i] = null;
				if(nulls == null) nulls = new LinkedList<Integer>();
				nulls.add(i);
			}
			else
				this.data[i] = new BigIntData(data[i]);
		}
		
	}
	public CryptoDataArray(ECPoint[] data)
	{
		super();
		this.data = new CryptoData[data.length];
		for(int i = 0; i < data.length; i++)
		{
			if(data[i] == null) {
				this.data[i] = null;
				if(nulls == null) nulls = new LinkedList<Integer>();
				nulls.add(i);
			}
			else
				this.data[i] = new ECPointData(data[i]);
		}
	}
	
	@Override
	public CryptoData getEmbeddedCryptoData(int[] index, int pos)
	{
		if(pos == index.length)
		{
			return data[index[pos]];
		}
		return data[index[pos]].getEmbeddedCryptoData(index, pos + 1);
	}
	
	@Override
	public void addFillDataHole(CryptoData d)
	{
		if(nulls == null) throw new ArrayIndexOutOfBoundsException("No nulls to fill in array");
		int index = nulls.get(0);
		if(data[index] == null)
		{
			data[index] = d;
			nulls.remove(0);
			if(nulls.size() == 0) nulls = null;
		}
		else 
		{
			data[index].addFillDataHole(d);
			if(!data[index].hasNull())
			{
				nulls.remove(0);
				if(nulls.size() == 0) nulls = null;
			}
		}
	}
	
//	@Override
//	public int addToEmbeddedCryptoData(int[] index, int pos, CryptoData d)
//	{
//		if(pos == index.length - 1)
//		{
//			int toReturn = 0;
//			if(data[index[pos]] == null) toReturn = 1;
//			data[index[pos]] = d;
//			return toReturn;
//		}
//		return data[index[pos]].addToEmbeddedCryptoData(index, pos + 1, d);
//	}
//	
//	@Override
//	public void replaceEmbeddedCryptoData(int[] index, int pos, CryptoData d)
//	{
//		if(pos == index.length - 1)
//		{
//			data[index[pos]] = d;
//		}
//		else data[index[pos]].addToEmbeddedCryptoData(index, pos + 1, d);
//	}
	
	@Override
	public CryptoData[] getCryptoDataArray() {
		return data;
	}

	@Override
	public int size() {
		// TODO Auto-generated method stub
		return data.length;
	}
	
	@Override
	public String toString()
	{
		StringBuilder strBuild = new StringBuilder();
		strBuild.append("[");
		for(int i = 0; i < data.length; i++)
		{
			if(data[i] != null)
			{
				strBuild.append(data[i].toString());
			}
			else  strBuild.append("NULL");
			if(i != data.length - 1) strBuild.append(",");
		}
		strBuild.append("]");
		return strBuild.toString();
	}
	@Override
	public String toString64()
	{
		StringBuilder strBuild = new StringBuilder();
		strBuild.append("[");
		for(int i = 0; i < data.length; i++)
		{
			strBuild.append(data[i].toString64());
			if(i != data.length - 1) strBuild.append(",");
		}
		strBuild.append("]");
		return strBuild.toString();
	}

	@Override
	public boolean hasNull() {
		return nulls != null;
	}

	@Override
	public byte[] getBytes() {
		byte[][] collectedBits = new byte[data.length][];
		for(int i = 0; i < data.length; i++)
		{
			collectedBits[i] = data[i].getBytes();
		}
		
		return Arrays.concatenate(collectedBits);
	}
}
