if {![namespace exists ::IMEX]} { namespace eval ::IMEX {} }
set ::IMEX::dataVar [file dirname [file normalize [info script]]]
set ::IMEX::libVar ${::IMEX::dataVar}/libs

create_library_set -name min\
   -timing\
    [list ${::IMEX::libVar}/mmmc/fast_vdd1v0_basicCells.lib]\
   -si\
    [list ${::IMEX::libVar}/mmmc/fast.cdb]
create_library_set -name max\
   -timing\
    [list ${::IMEX::libVar}/mmmc/slow_vdd1v0_basicCells.lib]\
   -si\
    [list ${::IMEX::libVar}/mmmc/slow.cdb]
create_op_cond -name all -library_file ${::IMEX::libVar}/mmmc/gsclib045_tech.tf -P 10 -V 10 -T 10
create_rc_corner -name all\
   -preRoute_res 1\
   -postRoute_res 1\
   -preRoute_cap 1\
   -postRoute_cap 1\
   -postRoute_xcap 1\
   -preRoute_clkres 0\
   -preRoute_clkcap 0\
   -qx_tech_file ${::IMEX::libVar}/mmmc/all/gpdk045.tch
create_delay_corner -name all\
   -rc_corner all\
   -early_library_set max\
   -late_library_set min
create_constraint_mode -name all\
   -sdc_files\
    [list ${::IMEX::dataVar}/mmmc/modes/all/all.sdc]
create_analysis_view -name all -constraint_mode all -delay_corner all -latency_file ${::IMEX::dataVar}/mmmc/views/all/latency.sdc
set_analysis_view -setup [list all] -hold [list all]
catch {set_interactive_constraint_mode [list all] } 
