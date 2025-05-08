package zero_knowledge_proofs;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

public class CVPProver extends SchnorrProver {
	@Override
	//input:  [commitment,key,message,initialCommSecret]
	//environment:  [messageGenerator(g),prime(p),keyGenerator(h)]
	//goal:  remove message from commitment and prove knowledge of the key.
	//Unsure as to how I should handle this.  I should probably handle this normally and 
	public boolean prove(ZKPData input, ZKPData environment, ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException, MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		BigInteger[] in1 = input.getBigIntArray();
		BigInteger[] e = environment.getBigIntArray();
		BigInteger[] in2 = new BigInteger[3];
		in2[0] = in1[1];
		in2[1] = in1[0].multiply(e[0].modPow(in1[2].negate(), e[1])).mod(e[1]); 
		in2[2] = in1[3];
		BigInteger[] e2 = new BigInteger[2];
		e2[0] = e[2];
		e2[1] = e[1];
		return super.prove(new BigIntArray(in2), new BigIntArray(e2), in, out);
		
	}
	@Override
	//input:  [commitment,message,response]
	//environment:  [messageGenerator(g),prime(p),keyGenerator(h)]
	//goal:  remove message from commitment and prove knowledge of the key.
	
	public ZKPData initialCommSim(ZKPData input, BigInteger challenge, ZKPData environment) {
		BigInteger[] in1 = input.getBigIntArray();
		BigInteger[] e = environment.getBigIntArray();
		BigInteger[] in2 = new BigInteger[3];
		in2[0] = in1[1];
		in2[1] = in1[0].multiply(e[0].modPow(in1[2].negate(), e[1])).mod(e[1]); 
		in2[2] = in1[3];
		BigInteger[] e2 = new BigInteger[2];
		e2[0] = e[2];
		e2[1] = e[1];
		return super.initialCommSim((new BigIntArray(in2), challenge, new BigIntArray(e2));
		
	}
	@Override
	public ZKPData calcResponse(ZKPData input, BigInteger challenge, ZKPData environment) {
		
	}
	

	@Override
	protected ZKPData simulatorGetResponse(ZKPData input) {
	}
}
