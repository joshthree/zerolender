import java.util.Scanner;

import zero_knowledge_proofs.VarianceToolkit;

public class ChooseTester {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Scanner in = new Scanner(System.in);
		while(true)
		{
			System.out.println("n and k");
			int n = in.nextInt();
			int k = in.nextInt();
			System.out.println(VarianceToolkit.choose(n, k));
		}
	}

}
