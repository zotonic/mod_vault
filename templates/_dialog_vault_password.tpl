
{% wire id=#form
		type="submit"
 		postback={vault_password name=name user_id=user_id}
 		delegate=`mod_vault` 
%}
<form id="{{ #form }}" action="postback">
	<p>{_ Change the password of the key: _} <strong>{{ name|escape }}</strong> ({{ user_id.title }})</p>

	<label>{_ Old password _}</label>
	<input type="password" id="{{ #old }}" name="old" value="" />
	{% validate id=#old name="old" type={presence} %}

	<label>{_ New password _}</label>
	<input type="password" id="{{ #new }}" name="new" value="" />
	{% validate id=#new name="new" type={presence} %}

	<div class="modal-footer">
		{% button class="btn" action={dialog_close} text=_"Cancel" tag="a" %}
		<button class="btn btn-primary" type="submit">{_ Change Password _}</button>
	</div>
</form>
