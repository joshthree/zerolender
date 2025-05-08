import java.math.BigInteger;
import java.util.Scanner;

import org.bouncycastle.util.encoders.Base64;

public class Tester {
	public static void main(String[] args)
	{
		Scanner in = new Scanner(System.in);
		String strNumber = in.nextLine();
		try
		{
			BigInteger number = new BigInteger(strNumber);
			System.out.println("If it is a BigInteger:");
			System.out.println(number);
			String encoded = new String(Base64.toBase64String(number.toByteArray()));
			System.out.println(encoded);
			
			BigInteger decoded = new BigInteger(Base64.decode((encoded)));
			System.out.println(decoded);
			
			System.out.println();
			
		}
		catch(Exception e)
		{
			System.out.println("Not a BigInteger");
		}

		System.out.println("If it is in Base64:");
		System.out.println(strNumber);
		BigInteger decoded = new BigInteger(Base64.decode((strNumber)));
		System.out.println(decoded.toString(16));
		
	}
}
