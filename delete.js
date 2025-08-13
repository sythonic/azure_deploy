if (field['Mirror of finding register.Remediation Due Date'] && field['Mirror of finding register.Remediation Due Date'].split("/").length === 3) {
	var arr = field['Mirror of finding register.Remediation Due Date'].split("/");
  	new Date(arr[2], arr[1] - 1, arr[0]);
} else if (field['Mirror of finding register.Date First Found'] && field['Mirror of finding register.Date First Found'].split("/").length === 3) {
  	var arr = field['Mirror of finding register.Date First Found'].split("/");
    var d = new Date(arr[2], arr[1] - 1, arr[0]);
    if (field['Mirror of finding register.Risk Rating - UNSW'] === "Low") {
        dateAdd('m', 2, d);
    } else if (field['Mirror of finding register.Risk Rating - UNSW'] === "Moderate") {
        dateAdd('m', 1, d);
    } else if (field['Mirror of finding register.Risk Rating - UNSW'] === "High" || field['Mirror of finding register.Risk Rating - UNSW'] === "Critical") {
        if (field['Assets1.Internet Facing'] == "Yes") {
            dateAdd('d', 2, d);
        } else {
            dateAdd('m', 1, d);
        }
    } else {
        d;
    }
} else if (field['Mirror of finding register.Create Date']) {
    var d = field['Mirror of finding register.Create Date']
    if (field['Mirror of finding register.Risk Rating - UNSW'] === "Low") {
        dateAdd('m', 2, d);
    } else if (field['Mirror of finding register.Risk Rating - UNSW'] === "Moderate") {
        dateAdd('m', 1, d);
    } else if (field['Mirror of finding register.Risk Rating - UNSW'] === "High" || field['Mirror of finding register.Risk Rating - UNSW'] === "Critical") {
        if (field['Assets1.Internet Facing'] == "Yes") {
            dateAdd('d', 2, d);
        } else {
            dateAdd('m', 1, d);
        }
    } else {
        d;
    }
} else {
	field['Mirror of finding register.Create Date'];
}



{% if risk_level == "Low" %}
    {% set due_date = date_found + relativedelta(months=2) %}
{% elif risk_level == "Moderate" %}
    {% set due_date = date_found + relativedelta(months=1) %}
{% elif risk_level in ["High", "Critical"] %}
    {% if internet_facing == "Yes" %}
        {% set due_date = date_found + relativedelta(days=2) %}
    {% else %}
        {% set due_date = date_found + relativedelta(months=1) %}
    {% endif %}
{% else %}
    {% set due_date = datetime.now() %}