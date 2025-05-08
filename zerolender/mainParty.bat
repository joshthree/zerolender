@echo off

setlocal enabledelayedexpansion
for /l %%x in (1, 1, 10) do (
	for /l %%y in (1, 1, %%x) do (
		echo n = %%x, k = %%y
		SET /a "_blah3=%%y-1"		
		echo start /W /MIN java -cp "./jars/bcprov-ext-jdk15on-157.jar;./bin" protocol.ProtocolMainECEfficientMultiSigWithFriends %2 %3 %4 Account%5_0.05_0.5_%%x_%%y P%1.0_Keys%5_0.05_0.5_%%x_%%y ecEnvironment 1 P%1_!_blah3!_friend	
		start /W /MIN java -cp "./jars/bcprov-ext-jdk15on-157.jar;./bin" protocol.ProtocolMainECEfficientMultiSigWithFriends %2 %3 %4 Account%5_0.05_0.5_%%x_%%y P%1.0_Keys%5_0.05_0.5_%%x_%%y ecEnvironment 1 P%1_!_blah3!_friend	

	)
)