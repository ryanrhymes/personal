
WIKISIM_URL = "http://probe-1.tb.hiit.fi:8080/query_by_url";
NEWSSIM_URL = "http://probe-1.tb.hiit.fi:8090/query_by_url";

function kvasir_submit() {
    my_url = $("#kvasir_search").val();
    query_simserver(my_url, "wiki");
}


// Query the simserver, either news or wiki.
function query_simserver(my_url, stype) {

    var simurl = ""

    if (stype == "wiki") {
        simurl = WIKISIM_URL
    } else if (stype == "news") {
        simurl = NEWSSIM_URL
    }

    $.ajax({
        type: "POST",
        url: simurl,
        data: {
            "url": my_url,
            "uid": ""
        },
        async: true,
        cache: false,
        success: function(html) {
	    //alert(html);
        }
    });

}