/* OpenBack sign-in button: editor side (plain script, no build step). The block is rendered by PHP. */
( function ( wp ) {
	var el = wp.element.createElement;
	var __ = wp.i18n.__;
	var InspectorControls = wp.blockEditor.InspectorControls;
	var useBlockProps = wp.blockEditor.useBlockProps;
	var PanelBody = wp.components.PanelBody;
	var TextControl = wp.components.TextControl;
	var ToggleControl = wp.components.ToggleControl;
	var ServerSideRender = wp.serverSideRender;

	wp.blocks.registerBlockType( 'openback-app-auth/login-button', {
		edit: function ( props ) {
			var a = props.attributes;
			return el(
				'div',
				useBlockProps(),
				el(
					InspectorControls,
					null,
					el(
						PanelBody,
						{ title: __( 'Button', 'openback-app-auth-wordpress' ) },
						el( TextControl, {
							label: __( 'Label (empty: the one of the settings)', 'openback-app-auth-wordpress' ),
							value: a.label,
							onChange: function ( v ) { props.setAttributes( { label: v } ); }
						} ),
						el( TextControl, {
							label: __( 'Address after sign-in (empty: this page)', 'openback-app-auth-wordpress' ),
							value: a.redirectTo,
							onChange: function ( v ) { props.setAttributes( { redirectTo: v } ); }
						} ),
						el( ToggleControl, {
							label: __( 'Show a sign-out link to signed-in visitors', 'openback-app-auth-wordpress' ),
							checked: !! a.showLogout,
							onChange: function ( v ) { props.setAttributes( { showLogout: v } ); }
						} )
					)
				),
				el( 'p', { className: 'openback-app-auth-editor-note' }, __( 'OpenBack sign-in button (visible to signed-out visitors).', 'openback-app-auth-wordpress' ) ),
				el( ServerSideRender, { block: 'openback-app-auth/login-button', attributes: a } )
			);
		},
		save: function () {
			return null;
		}
	} );
} )( window.wp );
