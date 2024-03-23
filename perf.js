import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
    stages: [
        { duration: "5s", target: 20 },
        { duration: "30s", target: 20 },
        { duration: "5s", target: 0 },
    ],
};

// Simulated user behavior
export default function() {
    let res = http.get("http://dsa4.fkm.filipton.space");
    // Validate response status
    check(res, { "status was 200": (r) => r.status == 200 });
}
