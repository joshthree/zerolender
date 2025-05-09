package zero_knowledge_proofs;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Base64;

import zero_knowledge_proofs.CryptoData.CryptoData;

public class DLPedersenCommitment implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = -5996322469501951428L;
	protected BigInteger commitment = null;
	
	public DLPedersenCommitment(BigInteger message, BigInteger keys, CryptoData env)
	{
		//g^m h^r mod p	
		CryptoData[] e = env.getCryptoDataArray();
		BigInteger p = e[0].getBigInt();
		BigInteger g = e[1].getBigInt();
		BigInteger h = e[2].getBigInt();

		this.commitment = g.modPow(message, p).multiply(h.modPow(keys, p)).mod(p);
	}
	private DLPedersenCommitment(BigInteger commitment)
	{
		this.commitment = commitment;
	}

	public BigInteger getCommitment() {
		return commitment;
	}

	public boolean verifyCommitment(BigInteger message, BigInteger keys, CryptoData env) {
		CryptoData[] e = env.getCryptoDataArray();
		BigInteger p = e[0].getBigInt();
		BigInteger g = e[1].getBigInt();
		BigInteger h = e[2].getBigInt();
	
		return commitment.equals(g.modPow(message, p).multiply(h.modPow(keys, p)).mod(p));

	}

	public DLPedersenCommitment multiplyCommitment(DLPedersenCommitment cmt, CryptoData env) {
		CryptoData[] e = env.getCryptoDataArray();
		return new DLPedersenCommitment(commitment.multiply(cmt.getCommitment()).mod(e[0].getBigInt()));
	}
	public String toString64()
	{
		return Base64.getEncoder().encodeToString(commitment.toByteArray());
	}	
}
