//SCANSPL  JOB (ACCT),'JES SPOOL TRIAGE',CLASS=A,MSGCLASS=H,
//         NOTIFY=&SYSUID
//*--------------------------------------------------------------
//* Runs collect/SCANSPL.rexx in batch under ISPF so the SDSF
//* REXX interface (ISFCALLS) is available. Dumps the result to
//* &OUTDSN in the format scan/jes_spool_triage.py expects.
//*
//* NOT VALIDATED against a live SDSF session -- see the big
//* warning at the top of SCANSPL.rexx before you submit this
//* against anything but a training/sandbox LPAR. The manual
//* fallback in the tool README works today without this JCL.
//*--------------------------------------------------------------
//STEP1    EXEC PGM=IKJEFT01,DYNAMNBR=100,REGION=0M
//SYSEXEC  DD DSN=YOUR.REXX.LIBRARY,DISP=SHR      <-- put SCANSPL here
//ISPPROF  DD DSN=&&ISPPROF,DISP=(,DELETE),
//            SPACE=(TRK,(5,5,5)),UNIT=SYSDA,
//            DCB=(RECFM=FB,LRECL=80,BLKSIZE=0,DSORG=PS)
//ISPLOG   DD SYSOUT=*
//ISPLIST  DD SYSOUT=*
//OUTDD    DD DSN=YOUR.HLQ.SCANSPL.OUT,DISP=(,CATLG,CATLG),
//            SPACE=(CYL,(5,5),RLSE),
//            DCB=(RECFM=FB,LRECL=132,BLKSIZE=0,DSORG=PS)
//SYSTSPRT DD SYSOUT=*
//SYSTSIN  DD *
  ISPSTART CMD(%SCANSPL) NEWAPPL(SDSF) NOPRINT
/*
