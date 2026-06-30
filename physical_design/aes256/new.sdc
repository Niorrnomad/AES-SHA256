create_clock -name i_clk  -period 4 [get_ports {i_clk}]

set_input_delay  -clock i_clk -max 1 [all_inputs]

set_output_delay -clock i_clk  -max 1 [all_outputs]

set_input_transition 0.1 [all_inputs]
set_load 0.2 [all_outputs]
