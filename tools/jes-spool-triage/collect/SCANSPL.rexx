/* REXX */
/*--------------------------------------------------------------------
 * SCANSPL -- SDSF REXX collector for jes-spool-triage.
 *
 * *** SCAFFOLD, NOT VALIDATED AGAINST A LIVE SDSF SESSION ***
 * The ISFCALLS/ISFEXEC/ISFACT shape below is the standard pattern for
 * driving SDSF from batch REXX, but the exact PARM()/PARM2() syntax
 * for the per-DD browse action varies by z/OS release and by what
 * your site's SDSFPARM allows an unauthorized user to do. Test this
 * against a sandbox/training LPAR -- never the live engagement box --
 * before you trust its output, and expect to tune the two sections
 * marked "TUNE THIS" below against your SDSF Guide and Reference.
 *
 * If you don't have time to tune this mid-engagement, skip it: build
 * the input file by hand instead. Open SDSF ST with PREFIX=* OWNER=*,
 * open the held output for a job you want to check, PRINT each DD you
 * care about (JESMSGLG, JESJCL, SYSTSIN, SYSIN, SYSPRINT) to a dataset
 * or to your terminal's log, and paste the lines under the right
 * ===JOB=== / ===DD=== headers yourself. The scanner doesn't care how
 * the file was produced.
 *
 * What this exec does when it works:
 *   1. ISFCALLS('ON') to get the SDSF REXX environment.
 *   2. ISFOWNER='*' ISFPREFIX='*' ; ISFEXEC 'ST' to list every job
 *      visible in the pool into JNAME./JOBID./OWNERID.* stems.
 *   3. For each job, browse the DDs we care about and write their
 *      lines to OUTDD in the format jes_spool_triage.py expects.
 *
 * Output DD: OUTDD (see SCANSPL.jcl), FB/132 or similar.
 *------------------------------------------------------------------*/

WANTED_DDS = 'JESMSGLG JESJCL JESYSMSG SYSTSIN SYSIN SYSPRINT'

rc = isfcalls('ON')
if rc <> 0 then do
  say 'SCANSPL: ISFCALLS(ON) failed, rc=' rc '-- are you running under ISPSTART in batch?'
  exit 16
end

isfprefix = '*'
isfowner  = '*'

address sdsf "ISFEXEC ST"
if rc <> 0 then do
  say 'SCANSPL: ISFEXEC ST failed, rc=' rc
  call isfcalls('OFF')
  exit 16
end

say 'SCANSPL: ' jname.0 ' jobs visible in the pool'

do i = 1 to jname.0

  jobname = strip(jname.i)
  jobid   = strip(jobid.i)
  owner   = strip(ownerid.i)
  class   = strip(jclass.i)

  call lineout 'OUTDD', '===JOB JOBNAME='jobname' JOBID='jobid' OWNER='owner' CLASS='class'==='

  /* ---------- TUNE THIS: per-job DD enumeration ----------
   * SDSF's REXX "?" (display DDs) row action against TOKEN(token.i)
   * is the usual way to get a job's DD list into a DDNAME. stem.
   * The exact ISFACT invocation differs by release; check your
   * SDSF Guide and Reference under "REXX support" / ISFACT for the
   * current syntax on your system. Sketch:
   *
   *   address sdsf "ISFACT ST TOKEN('"token.i"') PARM(NP ?)"
   *   ddcount = ddname.0
   *
   * Until that's confirmed on your system, fall back to the fixed
   * WANTED_DDS list above and just try to browse each by name.
   * --------------------------------------------------------- */

  do w = 1 to words(WANTED_DDS)
    ddn = word(WANTED_DDS, w)

    /* ---------- TUNE THIS: per-DD browse action ----------
     * The browse ("BR") row action against a job's DD, run through
     * ISFACT, is documented to return the browsed lines in the
     * ISFLINE. stem (ISFLINE.0 = count, ISFLINE.1..n = text).
     * Confirm the PARM()/PARM2() keywords your release expects --
     * this is the piece most likely to need adjustment.
     *
     *   address sdsf "ISFACT ST TOKEN('"token.i"') PARM(NP BR) ",
     *                "PARM2('DDNAME("ddn")')"
     * ------------------------------------------------------- */

    address sdsf "ISFACT ST TOKEN('"token.i"') PARM(NP BR) PARM2('DDNAME("ddn")')"

    if rc = 0 & symbol('ISFLINE.0') = 'VAR' then do
      if isfline.0 > 0 then do
        call lineout 'OUTDD', '===DD DDNAME='ddn'==='
        do n = 1 to isfline.0
          call lineout 'OUTDD', isfline.n
        end
      end
    end
    drop isfline.
  end

end

call lineout 'OUTDD'
call isfcalls('OFF')
say 'SCANSPL: done'
exit 0
