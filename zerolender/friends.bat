@echo off
setlocal enabledelayedexpansion
for /l %%x in (2, 1, 10) do (
	for /l %%y in (2, 1, %%x) do (
		echo n = %%x, k = %%y

		SET /a "_blah=%%y-3"
		for /l %%z in (0, 1, !_blah!) do (
			SET /a "_blah2=%%z+1"
			echo start /MIN java -cp "./jars/bcprov-ext-jdk15on-157.jar;./bin" protocol.ProtocolMainECMixedMalWithComparisonFriend %2 %3 %%z Account%4_0.05_0.5_%%x_%%y P%1.!_blah2!_Keys%4_0.05_0.5_%%x_%%y ecEnvironment
			start /MIN java -cp "./jars/bcprov-ext-jdk15on-157.jar;./bin" protocol.ProtocolMainECMixedMalWithComparisonFriend %2 %3 %%z Account%4_0.05_0.5_%%x_%%y P%1.!_blah2!_Keys%4_0.05_0.5_%%x_%%y ecEnvironment
		)
		SET /a "_blah=%%y-2"
		SET /a "_blah2=%%y-1"
		echo start /W /MIN java -cp "./jars/bcprov-ext-jdk15on-157.jar;./bin" protocol.ProtocolMainECMixedMalWithComparisonFriend %2 %3 !_blah! Account%4_0.05_0.5_%%x_%%y P%1.!_blah2!_Keys%4_0.05_0.5_%%x_%%y ecEnvironment
		start /W /MIN java -cp "./jars/bcprov-ext-jdk15on-157.jar;./bin" protocol.ProtocolMainECMixedMalWithComparisonFriend %2 %3 !_blah! Account%4_0.05_0.5_%%x_%%y P%1.!_blah2!_Keys%4_0.05_0.5_%%x_%%y ecEnvironment
	
	)
)
::for /l %%x in (1, 1, 10) do (
::echo test
::echo test2
::	for /l %%y in (2, 1, %%x) do (
::		for /l %%z in (1, 1, %%y) do (
			::SET blah=
			::SET /a 'blah=%%z-1'
			
::		)
		::echo start /W java -cp "./jars/bcprov-ext-jdk15on-157.jar;./bin" protocol.ProtocolMainECMixedMalWithComparisonFriend %2 %3 'SET /a %%y-2' Account1000_0.05_0.5_%%x_%%y P%1.'SET /a %%y-1'_Keys1000_0.05_0.5_%%x_%%y ecEnvironment
::	)
::)