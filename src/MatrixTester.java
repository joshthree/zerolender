import java.math.BigInteger;
import java.security.SecureRandom;

public class MatrixTester {

	public static void main(String[] args) {
		BigInteger[][] m = new BigInteger[][] {
			{BigInteger.valueOf(1),BigInteger.valueOf(0)},
			{BigInteger.valueOf(1),BigInteger.valueOf(2)},
		};
		
		
		BigInteger prime = BigInteger.probablePrime(10, new SecureRandom());
		prime = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
		System.out.println(prime);
	
		System.out.println(m.length);
		System.out.println(m[0].length);
		MatrixInterface matrix = new Matrix(m,prime);
		MatrixInterface inverse = matrix.getInverse();
		System.out.println(matrix);
		BigInteger[][] results = new BigInteger[][]{{new BigInteger("51887209488688196464753479880894180930917720434734304619987081190970959514383")},{new BigInteger("11802445044425220879413707126329076000116172729683863859325449849347034422081")}};
		MatrixInterface blah = new Matrix(results, prime);
		BigInteger[][] invArray = inverse.getMatrix();
		for(int i = 0; i < invArray.length; i++) {
			for(int j = 0; j < invArray.length; j++) {
				System.out.print(invArray[i][j]+", ");
			}
			System.out.println();
		}
		System.out.println();
		BigInteger[][] coefficients = blah.multiply(inverse).getMatrix();
		System.out.println();
		for(int i = 0; i < coefficients.length; i++) {
			System.out.println(coefficients[i][0]);
		}
		System.out.println(coefficients[0][0].add(coefficients[1][0].multiply(BigInteger.valueOf(2))).mod(prime));
	}

}
