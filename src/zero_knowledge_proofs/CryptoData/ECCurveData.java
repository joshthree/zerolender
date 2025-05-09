package zero_knowledge_proofs.CryptoData;

import java.math.BigInteger;
import java.security.spec.EllipticCurve;
import java.util.Base64;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public final class ECCurveData extends CryptoData {
	/**
	 * 
	 */
	private static final long serialVersionUID = 5968736215439976858L;
	private ECCurve c;
	private ECPoint g;
	
	public ECCurveData(ECCurve c, ECPoint g)
	{
		this.c = c;
		if(!g.isNormalized())
			g = g.normalize();
		this.g = g;
	}
	@Override
	public CryptoData[] getCryptoDataArray() {
		return null;
	}
	
	@Override
	public ECCurve getECCurveData() {
		 return c;
	}
	@Override
	public ECPoint getECPointData(ECCurve c) {
		if(this.c == c)
			return g;
		else return c.importPoint(g);
	}
	
	@Override
	public int size() {
		return 1;
	}

	@Override
	public String toString()
	{
		return String.format("y^2 = x^3 + %sx + %s, G = (%s, %s)", c.getA().toBigInteger().toString(16), c.getB().toBigInteger().toString(16), g.getAffineXCoord().toBigInteger().toString(16), g.getAffineYCoord().toBigInteger().toString(16));
	}
	@Override
	public String toString64()
	{
		return String.format("y^2 = x^3 + %sx + %s, G = (%s, %s)", Base64.getEncoder().encodeToString(c.getA().toBigInteger().toByteArray()), Base64.getEncoder().encodeToString(c.getB().toBigInteger().toByteArray()), Base64.getEncoder().encodeToString(g.getAffineXCoord().toBigInteger().toByteArray()), Base64.getEncoder().encodeToString(g.getAffineYCoord().toBigInteger().toByteArray()));
	}
	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		return g.getEncoded(true);
	}
}
