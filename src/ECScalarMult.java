import java.math.BigInteger;
import java.util.Scanner;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ECScalarMult {
	public static void main(String[] args)
	{
		ECPoint g = ECNamedCurveTable.getParameterSpec("secp256k1").getG();
		
		ECCurve curve = g.getCurve();
		Scanner in = new Scanner(System.in);
		System.out.println("Base:");
		int base = in.nextInt();
		System.out.println("Point x:");
		BigInteger x, y, r;
		String s;
		s = in.next();
		try {
			x = new BigInteger(s);
		}catch(NumberFormatException e)
		{
			x = new BigInteger(s, base);
		}
		System.out.println("Point y:");
		s = in.next();
		try {
			y = new BigInteger(s);
		}catch(NumberFormatException e)
		{
			y = new BigInteger(s, base);
		}
		System.out.println("mult:");
		s = in.next();
		try {
			r = new BigInteger(s);
		}catch(NumberFormatException e)
		{
			r = new BigInteger(s, base);
		}
		ECPoint p = curve.createPoint(x, y);
		System.out.println("\t" + p.multiply(r).normalize().getAffineXCoord());
		System.out.println("\t" + p.multiply(r).normalize().getAffineYCoord());
		
		
	}
}
