import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalParameters;


public class GeneratorMaker {
	public static void main(String[] args)
	{
		//Usage:  Executable numBits [seed]
		int numBits = Integer.parseInt(args[0]);
		SecureRandom r;
		if(args.length == 2)
			r = new SecureRandom(new BigInteger(args[1]).toByteArray());
		else
			r = new SecureRandom();
		ElGamalParametersGenerator pGen = new ElGamalParametersGenerator();
		pGen.init( numBits, 20, r );
		ElGamalParameters params = pGen.generateParameters();
		BigInteger p = params.getP();
		System.out.printf("p = %s\n", p);
		BigInteger order = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
		BigInteger g = params.getG();
		System.out.printf("g = %s\n", g);
		BigInteger h = p;
		while(h.compareTo(p) >= 0)
		{
			h = new BigInteger( numBits, r );
			if(h.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO))
			{
				h = h.add(BigInteger.ONE);
			}
			if(h.mod(order).equals(BigInteger.ZERO))
			{
				h = h.add(BigInteger.valueOf(2));
			}
		}
		System.out.printf("h = %s\n", h);
		
	}
}
