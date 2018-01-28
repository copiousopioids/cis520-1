--------------------------------------------------------------
               Zach Marcolesco - CIS520 - Project0

     DESCRIPTION: A Simple Assignment to Introduce pintOS.
--------------------------------------------------------------

All Modified files are in "/src/tests/threads/" .

Files to modify found by calling these commands in /src/tests:
  $ grep -r alarm-multiple
  $ grep -r test_alarm_multiple

Make.tests
  - Line 5: Added "alarm-mega"
  
Rubric.alarm
  - Inserted line 2: "4 alarm-mega"
  
tests.c
  - Inserted line 16: "  	{"alarm-mega", test_alarm_mega},"
  
tests.h
  - Inserted line 10: "extern test_func test_alarm_mega;"
  
alarm-wait.c
  - Added function at line 27:
        void
        test_alarm_mega (void) 
        {
          test_sleep (5, 70);
        }
        
alarm-mega.ck
  - Created file alarm-mega.ck, contents:
      # -*- perl -*-
      use tests::tests;
      use tests::threads::alarm;
      check_alarm (70);