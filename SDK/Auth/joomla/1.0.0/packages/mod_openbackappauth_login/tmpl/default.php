<?php

/**
 * OpenBack App Auth - Login button module: the button, or the sign-out form and the link to connect the account.
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 *
 * @var \Joomla\Registry\Registry       $params
 * @var \Joomla\CMS\User\User|null      $user
 * @var bool                            $available
 * @var bool                            $configured
 * @var string                          $loginUrl
 * @var string                          $linkUrl
 * @var string                          $label
 * @var string                          $return
 */

\defined('_JEXEC') or die;

use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

$escape = static fn (string $text): string => htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
$guest  = $user === null || $user->guest;
?>
<div class="mod-openbackappauth-login">
    <?php if (!$available || !$configured) : ?>
        <?php if (!$guest && $user->authorise('core.admin')) : ?>
            <p class="alert alert-warning"><?php echo Text::_('MOD_OPENBACKAPPAUTH_LOGIN_NOT_CONFIGURED'); ?></p>
        <?php endif; ?>
    <?php elseif ($guest) : ?>
        <a class="btn btn-primary mod-openbackappauth-login__button" href="<?php echo $escape($loginUrl); ?>" rel="nofollow">
            <?php echo $escape($label); ?>
        </a>
    <?php else : ?>
        <?php if ((int) $params->get('show_logout', 1) === 1) : ?>
            <form action="<?php echo $escape(Route::_('index.php?option=com_users&task=user.logout')); ?>" method="post" class="mod-openbackappauth-login__logout">
                <p><?php echo Text::sprintf('MOD_OPENBACKAPPAUTH_LOGIN_SIGNED_IN_AS', $escape((string) $user->name)); ?></p>
                <button type="submit" class="btn btn-secondary"><?php echo Text::_('JLOGOUT'); ?></button>
                <input type="hidden" name="return" value="<?php echo $escape(base64_encode($return)); ?>">
                <?php echo HTMLHelper::_('form.token'); ?>
            </form>
        <?php endif; ?>
        <?php if ($linkUrl !== '') : ?>
            <p class="mod-openbackappauth-login__link">
                <a href="<?php echo $escape($linkUrl); ?>" rel="nofollow"><?php echo Text::_('MOD_OPENBACKAPPAUTH_LOGIN_LINK_ACCOUNT'); ?></a>
            </p>
        <?php endif; ?>
    <?php endif; ?>
</div>
