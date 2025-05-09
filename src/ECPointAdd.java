import java.math.BigInteger;
import java.util.Scanner;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ECPointAdd {
	public static void main(String[] args)
	{
		
		ECPoint g = ECNamedCurveTable.getParameterSpec("secp256k1").getG();
		
		ECCurve curve = g.getCurve();
		Scanner in = new Scanner(System.in);
		System.out.println("Point x1:");
		BigInteger x1, y1, x2, y2;
		String s;
		s = in.next();
		try {
			x1 = new BigInteger(s);
		}catch(NumberFormatException e)
		{
			x1 = new BigInteger(s, 16);
		}
		System.out.println("Point y1:");
		s = in.next();
		try {
			y1 = new BigInteger(s);
		}catch(NumberFormatException e)
		{
			y1 = new BigInteger(s, 16);
		}
		System.out.println("Point x2:");
		s = in.next();
		try {
			x2 = new BigInteger(s);
		}catch(NumberFormatException e)
		{
			x2 = new BigInteger(s, 16);
		}
		System.out.println("Point y2:");
		s = in.next();
		try {
			y2 = new BigInteger(s);
		}catch(NumberFormatException e)
		{
			y2 = new BigInteger(s, 16);
		}
		ECPoint p1 = curve.createPoint(x1, y1);
		ECPoint p2 = curve.createPoint(x2, y2);
		System.out.println("\t" + p1.add(p2).normalize().getAffineXCoord());
		System.out.println("\t" + p1.add(p2).normalize().getAffineYCoord());
	}
}
