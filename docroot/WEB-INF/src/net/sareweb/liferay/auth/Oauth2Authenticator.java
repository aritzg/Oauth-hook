package net.sareweb.liferay.auth;

import java.util.Locale;
import java.util.Map;

import net.sareweb.liferay.auth.google.Checker;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.exception.SystemException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.MethodKey;
import com.liferay.portal.kernel.util.PortalClassInvoker;
import com.liferay.portal.model.User;
import com.liferay.portal.security.auth.AuthException;
import com.liferay.portal.security.auth.Authenticator;
import com.liferay.portal.service.ServiceContext;
import com.liferay.portal.service.UserLocalServiceUtil;
import com.liferay.portal.util.PortalUtil;

public class Oauth2Authenticator implements Authenticator {

	Log _log = LogFactoryUtil.getLog(this.getClass());

	public int authenticateByEmailAddress(long arg0, String email,
			String tokenOrPass, Map<String, String[]> arg3,
			Map<String, String[]> arg4) throws AuthException {
		_log.debug("authenticateByEmailAddress " + email);
		if (isMobileRequest(arg3)) {
			try {
				return authentiateWithGoogleToken(email, tokenOrPass);
			} catch (Exception e) {
				return authentiateWithLiferayPass(email, tokenOrPass);
			}
		} else {
			return authentiateWithLiferayPass(email, tokenOrPass);
		}
	}

	public int authenticateByScreenName(long arg0, String arg1, String arg2,
			Map<String, String[]> arg3, Map<String, String[]> arg4)
			throws AuthException {
		_log.debug("authenticateByScreenName");
		return Authenticator.FAILURE;
	}

	public int authenticateByUserId(long arg0, long arg1, String arg2,
			Map<String, String[]> arg3, Map<String, String[]> arg4)
			throws AuthException {
		_log.debug("authenticateByUserId");
		return Authenticator.FAILURE;
	}

	private int authentiateWithGoogleToken(String email, String token) {
		String[] clientIDs = { "532011836106-mepq06u0d4hdihknuqlc6gbalj7hq2ti.apps.googleusercontent.com" };
		Checker checker = new Checker(clientIDs,
				"532011836106-0ut2n2qf7mil507lkiv27u6ggaj90m5s.apps.googleusercontent.com");
		GoogleIdToken.Payload payload = checker.check(token);
		if (payload == null) {
			_log.error("checker.problem() " + checker.problem());
			return Authenticator.FAILURE;
		} else {
			_log.debug("payload.getEmail() " + payload.getEmail());
			if (!doesUserExist(payload.getEmail())) {
				_log.debug("User did not exist alf will be created for mobile access");
				try {
					addUser(payload.getEmail());
				} catch (Exception e) {
					_log.error("Error creating user", e);
					return Authenticator.FAILURE;
				}
			}
			return Authenticator.SUCCESS;
		}
	}

	private int authentiateWithLiferayPass(String email, String password) {
		try {
			MethodKey mkAuth = new MethodKey(
					"com.liferay.portal.security.pwd.PwdAuthenticator",
					"authenticate", String.class, String.class, String.class);
			User u = null;
			;
			try {
				u = UserLocalServiceUtil.getUserByEmailAddress(
						PortalUtil.getDefaultCompanyId(), email);
			} catch (Exception e) {
				_log.debug("No such user?");
				return Authenticator.FAILURE;
			}

			Boolean authenticated = (Boolean) PortalClassInvoker.invoke(false,
					mkAuth, email, password, u.getPassword());
			if (authenticated.booleanValue()) {
				return Authenticator.SUCCESS;
			}
		} catch (Exception e) {
			_log.error("Error authenticating user", e);
		}
		return Authenticator.FAILURE;
	}

	private boolean isMobileRequest(Map<String, String[]> arg3) {
		String[] ua = arg3.get("user-agent");
		return ua[0].indexOf("Apache-HttpClient") != -1;
	}

	private boolean doesUserExist(String emailAddress) {
		try {
			UserLocalServiceUtil.getUserByEmailAddress(
					PortalUtil.getDefaultCompanyId(), emailAddress);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public User addUser(String emailAddress) throws PortalException,
			SystemException {
		return addUser(emailAddress, emailAddress, emailAddress, emailAddress);
	}

	public User addUser(String email, String nombre, String apellido1,
			String apellido2) throws PortalException, SystemException {
		ServiceContext sc = new ServiceContext();
		return UserLocalServiceUtil.addUser(0,
				PortalUtil.getDefaultCompanyId(), true, "test", "test", true, // autoScreenName
				null, // screenName
				email,// emailAddress
				0, // facebookId
				"", // openId
				new Locale("eu", "ES"), // locale
				nombre, // firstName
				apellido1, // middleName
				apellido2, // lastName,
				0,// prefixId
				0, // suffixId,
				true, // male
				1,// birthdayMonth
				1,// birthdayDay
				2000, // birthdayYear,
				"", // jobTitle
				new long[0], // groupIds
				new long[0], // organizationIds
				new long[0], // roleIds,
				new long[0], // userGroupIds,
				true, // sendEmail
				sc);// , serviceContext)
	}

}
