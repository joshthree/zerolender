package zero_knowledge_proofs;

import java.math.BigInteger;

public class ECPedersenOwnedBitwiseCommitment{
	protected ECPedersenOwnedBitwiseCommitment()
	{
		
	}
	protected ECPedersenCommitment[] comm;
	protected BigInteger m;
	protected BigInteger[] keys;
	
	public BigInteger getMessage()
	{
		return m;
	}
	
	public BigInteger[] getKeys()
	{
		return keys.clone();
	}
	
	public ECPedersenCommitment[] getComm()
	{
		return comm.clone();
	}
}
