package zero_knowledge_proofs;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Base64;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.CryptoData.CryptoData;

public class ECPedersenCommitmentOld implements Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -4464353885259184169L;
	protected BigInteger x;
	protected BigInteger y;
	
	
	public ECPedersenCommitmentOld(BigInteger message, BigInteger keys, CryptoData environment)
	{
		//g^m h^r 
		ECCurve c = environment.getCryptoDataArray()[0].getECCurveData();
		ECPoint g = environment.getCryptoDataArray()[0].getECPointData(c);
		ECPoint h = environment.getCryptoDataArray()[1].getECPointData(c);
		ECPoint comm = g.multiply(message).add(h.multiply(keys));
		comm = comm.normalize();
		if(comm.getXCoord() == null)
		{
			x = y = null;
		}
		else
		{
			x = comm.getAffineXCoord().toBigInteger();
			y = comm.getAffineYCoord().toBigInteger();
		}
	}
	private ECPedersenCommitmentOld(ECPoint comm)
	{
		comm = comm.normalize();
		if(comm.getXCoord() == null)
		{
			x = y = null;
		}
		else
		{
			x = comm.getAffineXCoord().toBigInteger();
			y = comm.getAffineYCoord().toBigInteger();
		}
	}

	public ECPoint getCommitment(CryptoData environment) {
		ECCurve c = environment.getCryptoDataArray()[0].getECCurveData();
		if (x == null) return c.getInfinity();
		return c.createPoint(x, y);
	}

	public boolean verifyCommitment(BigInteger message, BigInteger keys, CryptoData environment) {
		ECCurve c = environment.getCryptoDataArray()[0].getECCurveData();
		ECPoint g = environment.getCryptoDataArray()[0].getECPointData(c);
		ECPoint h = environment.getCryptoDataArray()[1].getECPointData(c);
		ECPoint comm = g.multiply(message).add(h.multiply(keys));
		return getCommitment(environment).equals(comm);
	}

	public ECPedersenCommitmentOld multiplyCommitment(ECPedersenCommitmentOld cmt, CryptoData environment) {
		
		return new ECPedersenCommitmentOld(cmt.getCommitment(environment).add(getCommitment(environment)));
	}
	public ECPedersenCommitmentOld multiplyShiftedCommitment(ECPedersenCommitmentOld cmt, int lShift, CryptoData environment) {
		
		return new ECPedersenCommitmentOld((cmt.getCommitment(environment).multiply(BigInteger.ONE.shiftLeft(lShift))).add(getCommitment(environment)));
	}
	
	public String toString64()
	{
		return String.format("(%s,%s)", Base64.getEncoder().encodeToString(x.toByteArray()),Base64.getEncoder().encodeToString(y.toByteArray()));
	}
	
}
