package zero_knowledge_proofs.CryptoData;
import java.math.BigInteger;

public interface MatrixInterface {
	BigInteger[][] getMatrix();
	MatrixInterface getInverse();
	MatrixInterface multiply(MatrixInterface m);
	
	BigInteger getModulus();
	int xDim();
	int yDim();
}
