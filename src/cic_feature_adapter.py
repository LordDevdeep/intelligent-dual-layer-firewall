import joblib
import pandas as pd
from pathlib import Path

MODEL_PATH = "/home/lorddevdeep/resolute/models/resolute_random_forest.joblib"


def adapt_cicflow_features(flow_data):
    model = joblib.load(MODEL_PATH)

    # CICFlowMeter field -> trained CIC-IDS2017 model field
    mapping = {
        "dst_port": "Destination_Port",
        "flow_duration": "Flow_Duration",

        "tot_fwd_pkts": "Total_Fwd_Packets",
        "tot_bwd_pkts": "Total_Backward_Packets",
        "totlen_fwd_pkts": "Total_Length_of_Fwd_Packets",
        "totlen_bwd_pkts": "Total_Length_of_Bwd_Packets",

        "fwd_pkt_len_max": "Fwd_Packet_Length_Max",
        "fwd_pkt_len_min": "Fwd_Packet_Length_Min",
        "fwd_pkt_len_mean": "Fwd_Packet_Length_Mean",
        "fwd_pkt_len_std": "Fwd_Packet_Length_Std",

        "bwd_pkt_len_max": "Bwd_Packet_Length_Max",
        "bwd_pkt_len_min": "Bwd_Packet_Length_Min",
        "bwd_pkt_len_mean": "Bwd_Packet_Length_Mean",
        "bwd_pkt_len_std": "Bwd_Packet_Length_Std",

        "flow_byts_s": "Flow_Bytes/s",
        "flow_pkts_s": "Flow_Packets/s",

        "flow_iat_mean": "Flow_IAT_Mean",
        "flow_iat_std": "Flow_IAT_Std",
        "flow_iat_max": "Flow_IAT_Max",
        "flow_iat_min": "Flow_IAT_Min",

        "fwd_iat_tot": "Fwd_IAT_Total",
        "fwd_iat_mean": "Fwd_IAT_Mean",
        "fwd_iat_std": "Fwd_IAT_Std",
        "fwd_iat_max": "Fwd_IAT_Max",
        "fwd_iat_min": "Fwd_IAT_Min",

        "bwd_iat_tot": "Bwd_IAT_Total",
        "bwd_iat_mean": "Bwd_IAT_Mean",
        "bwd_iat_std": "Bwd_IAT_Std",
        "bwd_iat_max": "Bwd_IAT_Max",
        "bwd_iat_min": "Bwd_IAT_Min",

        "fwd_psh_flags": "Fwd_PSH_Flags",
        "bwd_psh_flags": "Bwd_PSH_Flags",
        "fwd_urg_flags": "Fwd_URG_Flags",
        "bwd_urg_flags": "Bwd_URG_Flags",

        "fwd_header_len": "Fwd_Header_Length",
        "bwd_header_len": "Bwd_Header_Length",

        "fwd_pkts_s": "Fwd_Packets/s",
        "bwd_pkts_s": "Bwd_Packets/s",

        "pkt_len_min": "Min_Packet_Length",
        "pkt_len_max": "Max_Packet_Length",
        "pkt_len_mean": "Packet_Length_Mean",
        "pkt_len_std": "Packet_Length_Std",
        "pkt_len_var": "Packet_Length_Variance",

        "fin_flag_cnt": "FIN_Flag_Count",
        "syn_flag_cnt": "SYN_Flag_Count",
        "rst_flag_cnt": "RST_Flag_Count",
        "psh_flag_cnt": "PSH_Flag_Count",
        "ack_flag_cnt": "ACK_Flag_Count",
        "urg_flag_cnt": "URG_Flag_Count",
        "cwr_flag_count": "CWE_Flag_Count",
        "ece_flag_cnt": "ECE_Flag_Count",

        "down_up_ratio": "Down/Up_Ratio",
        "pkt_size_avg": "Average_Packet_Size",

        "fwd_seg_size_avg": "Avg_Fwd_Segment_Size",
        "bwd_seg_size_avg": "Avg_Bwd_Segment_Size",

        "fwd_byts_b_avg": "Fwd_Avg_Bytes/Bulk",
        "fwd_pkts_b_avg": "Fwd_Avg_Packets/Bulk",
        "fwd_blk_rate_avg": "Fwd_Avg_Bulk_Rate",

        "bwd_byts_b_avg": "Bwd_Avg_Bytes/Bulk",
        "bwd_pkts_b_avg": "Bwd_Avg_Packets/Bulk",
        "bwd_blk_rate_avg": "Bwd_Avg_Bulk_Rate",

        "subflow_fwd_pkts": "Subflow_Fwd_Packets",
        "subflow_fwd_byts": "Subflow_Fwd_Bytes",
        "subflow_bwd_pkts": "Subflow_Bwd_Packets",
        "subflow_bwd_byts": "Subflow_Bwd_Bytes",

        "init_fwd_win_byts": "Init_Win_bytes_forward",
        "init_bwd_win_byts": "Init_Win_bytes_backward",

        "fwd_act_data_pkts": "act_data_pkt_fwd",
        "fwd_seg_size_min": "min_seg_size_forward",

        "active_mean": "Active_Mean",
        "active_std": "Active_Std",
        "active_max": "Active_Max",
        "active_min": "Active_Min",

        "idle_mean": "Idle_Mean",
        "idle_std": "Idle_Std",
        "idle_max": "Idle_Max",
        "idle_min": "Idle_Min",
    }

    mapped = {}

    for source_name, model_name in mapping.items():
        if source_name in flow_data:
            mapped[model_name] = flow_data[source_name]

    # CIC-IDS2017 contains a duplicated forward-header-length feature.
    # CICFlowMeter calculates the value once, so use the same value twice.
    if "Fwd_Header_Length" in mapped:
        mapped["Fwd_Header_Length_duplicated_0"] = mapped["Fwd_Header_Length"]

    expected = list(model.feature_names_in_)

    missing = [name for name in expected if name not in mapped]

    if missing:
        raise ValueError(
            "Missing model features:\n" + "\n".join(missing)
        )

    # Exact feature order required by the trained Random Forest.
    result = pd.DataFrame(
        [[mapped[name] for name in expected]],
        columns=expected
    )

    return result
