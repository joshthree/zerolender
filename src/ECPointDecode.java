import java.math.BigInteger;
import java.util.Base64;
import java.util.Scanner;
import java.util.Base64.Decoder;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;


public class ECPointDecode {
	public static void main(String[] args)
	{
		ECPoint g = ECNamedCurveTable.getParameterSpec("secp256k1").getG();

		ECCurve curve = g.getCurve();
		Scanner in = new Scanner(System.in);
		System.out.println("Base:");
		int base = in.nextInt();
		System.out.println("Encoded Point");
		BigInteger x;
		String s;
		s = in.next();
		if(base == 64)
		{
			Decoder decoder = Base64.getDecoder();
			x = new BigInteger(decoder.decode(s));
		}
		else {
			try {
				x = new BigInteger(s);
			}catch(NumberFormatException e)
			{
				x = new BigInteger(s, base);
			}	
		}
		System.out.println(g.getCurve().decodePoint(x.toByteArray()).normalize().getAffineXCoord());
		System.out.println(g.getCurve().decodePoint(x.toByteArray()).normalize().getAffineYCoord());
		
	}
}
