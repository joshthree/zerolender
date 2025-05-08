import java.math.BigInteger;
import java.util.Scanner;

public class Convert16to10 {
	public static void main(String[] args)
	{
		Scanner in = new Scanner(System.in);
		System.out.println("Number:");
		String num = in.next();
		System.out.println(new BigInteger(num).toString(16));
	}
}
