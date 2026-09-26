                   FUNCTION:NAME
                          :BEGIN 


                1

              libdtrace.so.2.0.0`BEGIN_probe
              {ptr}
                1
-- @@stderr --
dtrace: script 'test/unittest/funcs/tst.subr.d' matched 43 probes
dtrace: error in dt_clause_8 for probe ID 1 (dtrace:::BEGIN): invalid address ({ptr}) at BPF pc NNN
dtrace: error in dt_clause_9 for probe ID 1 (dtrace:::BEGIN): invalid address ({ptr}) at BPF pc NNN
