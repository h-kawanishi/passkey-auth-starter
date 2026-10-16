// users / credentials / sessions / reset_tokens / login_attempts / audit_log への読み書き。
// SQL はこのファイルに集め、ルートや auth/ からは関数として呼ぶ（SQL がアプリ中に散らばると、
// 「秘密の生値を保存していないか」をレビューで確かめにくくなるため）。
//
// TODO(B): users・sessions・login_attempts・audit_log の読み書き
// TODO(C): credentials の読み書き
// TODO(D): reset_tokens の読み書き
export {};
