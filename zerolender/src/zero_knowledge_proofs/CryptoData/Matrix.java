package zero_knowledge_proofs.CryptoData;
import java.math.BigInteger;

public class Matrix implements MatrixInterface {

	private BigInteger[][] matrix_;
	private BigInteger prime;
	public Matrix(BigInteger[][] matrix, BigInteger p) {
		prime = p;
		if(!p.isProbablePrime(50)) throw new IllegalArgumentException("p must be prime");
		matrix_ = new BigInteger[matrix.length][matrix[0].length];
		for(int i = 0; i < matrix.length; i++) {
			if(matrix[0].length != matrix[i].length) throw new ArrayIndexOutOfBoundsException("Matricies must be rectangular");
			for(int j = 0; j < matrix[i].length; j++) {
				if(matrix[i][j] == null) throw new NullPointerException("Null in matrix at " + i + ", " + j);
				matrix_[i][j] = matrix[i][j];
			}
		}
	}
	private Matrix(BigInteger[][] matrix, BigInteger p, boolean doesntmatter) {
		prime = p;
		matrix_ = matrix;
	}
	
	@Override
	public BigInteger[][] getMatrix() {
		BigInteger[][] matrix = new BigInteger[matrix_.length][matrix_[0].length];
		for(int i = 0; i < matrix_.length; i++) {
			if(matrix_[0].length != matrix_[i].length) throw new ArrayIndexOutOfBoundsException("Matricies must be rectangular");
			for(int j = 0; j < matrix_[i].length; j++) {
				matrix[i][j] = matrix_[i][j];
			}
		}
		
		return matrix;
	}

	@Override
	public MatrixInterface getInverse() {
		if(matrix_.length != matrix_[0].length) throw new UnsupportedOperationException("Matrix must be square");
		
		int size = matrix_.length;
		BigInteger[][] matrix = getMatrix();
		BigInteger[][] otherMatrix = new BigInteger[matrix.length][matrix.length];
		
		for(int i = 0; i < size; i++) {
			for(int j = 0; j < size; j++) {
				otherMatrix[i][j] = BigInteger.ZERO;
			}
		}

		for(int i = 0; i < size; i++) {
			if(matrix[i][i].equals(BigInteger.ZERO)) throw new UnsupportedOperationException("Inverse can not be calculated.");
			BigInteger valueInverse = matrix[i][i].modInverse(prime);
			otherMatrix[i][i] = BigInteger.ONE;
			
			for(int j = 0; j < size; j++)
			{
				matrix[i][j] = matrix[i][j].multiply(valueInverse).mod(prime);
				otherMatrix[i][j] = otherMatrix[i][j].multiply(valueInverse).mod(prime);
			}
			for(int k = i+1; k < size; k++) {
				BigInteger factor = matrix[k][i];
				for(int j = 0; j < size; j++) {
					matrix[k][j] = matrix[k][j].subtract(matrix[i][j].multiply(factor)).mod(prime);
					otherMatrix[k][j] = otherMatrix[k][j].subtract(otherMatrix[i][j].multiply(factor)).mod(prime);
				}
			}
		}
		
		for(int i = size-2; i >= 0; i--) {
			for(int j = i+1; j < size; j++) {
				BigInteger factor = matrix[i][j];
				matrix[i][j] = BigInteger.ZERO;
				for(int k = 0; k < size; k++) {
					otherMatrix[i][k] = otherMatrix[i][k].subtract(otherMatrix[j][k].multiply(factor).mod(prime)).mod(prime); 
				}
			}
			
		}
		
		MatrixInterface m = new Matrix(otherMatrix, prime, true);
		
		return m;
	}


	@Override
	public int xDim() {
		return matrix_[0].length;
	}

	@Override
	public int yDim() {
		return matrix_.length;
	}

	@Override
	public MatrixInterface multiply(MatrixInterface m) {
		if(m.xDim() != yDim()) throw new UnsupportedOperationException("Invalid Matrix Dimensions");
		if(!(m.getModulus().equals(getModulus()))) throw new UnsupportedOperationException("Moduli are not equal");
		BigInteger[][] otherMatrix = m.getMatrix();
		BigInteger[][] result = new BigInteger[yDim()][xDim()];
		
		int y = yDim();
		System.out.println(y);
		for(int i = 0; i < result.length; i++) {
			for(int j = 0; j < result[0].length; j++) {
				result[i][j] = BigInteger.ZERO;
				for(int k = 0; k < y; k++) {
//					System.out.println(matrix_[k][j]);
//					System.out.println(otherMatrix[k][j]);
//					System.out.println(result[k][j]);
//					System.out.println();
					result[i][j] = result[i][j].add(matrix_[k][j].multiply(otherMatrix[i][k]).mod(prime));
				}
				result[i][j] = result[i][j].mod(prime);
			}
		}
		
		return new Matrix(result, prime, true);
	}

	@Override
	public BigInteger getModulus() {
		return prime;
	}
	@Override
	public String toString() {
		StringBuilder s = new StringBuilder();
		s.append("[");
		for(int i = 0; i < matrix_.length; i++) {

			s.append("\n[");
			for(int j = 0; j < matrix_[0].length; j++) {
				s.append(matrix_[i][j]);
				if(j != matrix_[0].length - 1) {
					s.append(", ");
				}
			}

			s.append("]");
		}
		s.append("]");
		return s.toString();
	}
}
