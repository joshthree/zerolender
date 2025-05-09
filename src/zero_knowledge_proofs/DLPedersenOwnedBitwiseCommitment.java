package zero_knowledge_proofs;

import java.math.BigInteger;

public class DLPedersenOwnedBitwiseCommitment {
	protected DLPedersenOwnedBitwiseCommitment()
	{
		
	}
	protected DLPedersenCommitment[] comm;
	protected BigInteger m;
	protected BigInteger[] keys;
	public DLPedersenCommitment[] getComm()
	{
		return comm.clone();
	}
}
