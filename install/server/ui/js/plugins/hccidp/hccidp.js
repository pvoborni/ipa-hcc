//
// IPA plugin for Hybrid Cloud Console
// Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
// See COPYING for license
//

define(["freeipa/phases", "freeipa/ipa", "freeipa/text"], function (
  phases,
  IPA,
  text
) {
  var hcc_idp_plugin = {};

  // helper function
  function get_item(array, attr, value) {
    for (var i = 0, l = array.length; i < l; i++) {
      if (array[i][attr] === value) return array[i];
    }
    return null;
  }

  // Extend IdP provider array
  hcc_idp_plugin.add_hcc_idp_templates_op = function () {
    // add new providers
    IPA.idp.templates.push({
      value: "sso.redhat.com",
      label: text.get("@i18n:objects.idp.template_sso_redhat_com"),
      fields: []
    });
    IPA.idp.templates.push({
      value: "sso.stage.redhat.com",
      label: text.get("@i18n:objects.idp.template_sso_stage_redhat_com"),
      fields: []
    });
    // refresh provider options
    var idpsetup = get_item(
      IPA.idp.spec.adder_dialog.sections,
      "name",
      "idpsetup"
    );
    var provider = get_item(idpsetup.fields, "name", "ipaidpprovider");
    provider.options = IPA.create_options(IPA.idp.templates);
    return true;
  };

  phases.on("customization", hcc_idp_plugin.add_hcc_idp_templates_op);

  return hcc_idp_plugin;
});
